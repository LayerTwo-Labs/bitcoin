// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <bmmcache.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <sidechain.h>
#include <sidechainclient.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <txdb.h>
#include <validation.h>

#include <wallet/wallet.h>

#include <algorithm>
#include <utility>

static const uint64_t nRefundOutputSize = 34;

namespace node {
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    // Limit weight to between 4K and DEFAULT_BLOCK_MAX_WEIGHT for sanity:
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, 4000, DEFAULT_BLOCK_MAX_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{mempool},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
}
static BlockAssembler::Options ConfiguredOptions()
{
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool)
    : BlockAssembler(chainstate, mempool, ConfiguredOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, const uint256& hashPrevBlock, CAmount* nFeesOut)
{
    if (!CheckMainchainConnection()) {
        LogPrintf("%s: Error: Cannot generate new BMM block without mainchain connection!\n", __func__);
        return nullptr;
    }

    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if (!pblocktemplate.get()) {
        return nullptr;
    }
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(::cs_main);

    CBlockIndex* pindexPrev = nullptr;
    if (hashPrevBlock.IsNull()) {
        pindexPrev = m_chainstate.m_chain.Tip();
    } else {
        pindexPrev = m_chainstate.m_chainman.m_blockman.LookupBlockIndex(hashPrevBlock);
        if (!pindexPrev) {
            LogPrintf("%s: Specified prevblock: %s does not exist!\n", __func__, hashPrevBlock.ToString());
            return nullptr;
        }
    }

    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    // Try to create a Withdrawal Bundle for this block. We want to know if a Withdrawal Bundle is going to
    // be generated because we will skip adding refund transactions to the
    // same block as a Withdrawal Bundle. We will add the Withdrawal Bundle to the block later if created.
    CTransactionRef withdrawalBundleTx;
    CTransactionRef withdrawalBundleDataTx;
    bool fCreatedWithdrawalBundle = false;
    if (CreateWithdrawalBundleTx(nHeight, withdrawalBundleTx, withdrawalBundleDataTx, false /* fReplicationCheck */,
                true /* fCheckUnique */)) {
        fCreatedWithdrawalBundle = true;
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    std::vector<CTxMemPool::txiter> vRefund;
    if (m_mempool) {
        LOCK(m_mempool->cs);
        addPackageTxs(*m_mempool, nPackagesSelected, nDescendantsUpdated, vRefund, !fCreatedWithdrawalBundle);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    SidechainClient client;

    // Create Withdrawal Bundle status updates
    // Lookup the current Withdrawal Bundle
    SidechainWithdrawalBundle withdrawalBundle;
    uint256 hashCurrentWithdrawalBundle;
    psidechaintree->GetLastWithdrawalBundleHash(hashCurrentWithdrawalBundle);
    if (psidechaintree->GetWithdrawalBundle(hashCurrentWithdrawalBundle, withdrawalBundle)) {
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_CREATED) {
            // Check if the Withdrawal Bundle has been paid out or failed
            if (client.HaveFailedWithdrawalBundle(hashCurrentWithdrawalBundle)) {
                CScript script = GenerateWithdrawalBundleFailCommit(hashCurrentWithdrawalBundle);
                coinbaseTx.vout.push_back(CTxOut(0, script));
            }
            else
            if (client.HaveSpentWithdrawalBundle(hashCurrentWithdrawalBundle)) {
                CScript script = GenerateWithdrawalBundleSpentCommit(hashCurrentWithdrawalBundle);
                coinbaseTx.vout.push_back(CTxOut(0, script));
            }
        }
    }

    // Add previous sidechain block hash & previous mainchain block hash to
    // the coinbase.
    CScript scriptPrev = GeneratePrevBlockCommit(bmmCache.GetLastMainBlockHash(), pindexPrev->GetBlockHash());
    coinbaseTx.vout.push_back(CTxOut(0, scriptPrev));

    // Add current hashWithdrawalBundle to coinbase output
    if (!hashCurrentWithdrawalBundle.IsNull()) {
        CScript scriptWithdrawalBundle = GenerateWithdrawalBundleHashCommit(hashCurrentWithdrawalBundle);
        coinbaseTx.vout.push_back(CTxOut(0, scriptWithdrawalBundle));
    }

    // Add block version to coinbase output
    CScript scriptVersion = GenerateBlockVersionCommit(pblock->nVersion);
    coinbaseTx.vout.push_back(CTxOut(0, scriptVersion));

    // Add Withdrawal Bundle to block if one was created earlier
    if (fCreatedWithdrawalBundle) {
        for (const CTxOut& out : withdrawalBundleDataTx->vout)
            coinbaseTx.vout.push_back(out);
    }

    // Create refund payout output(s) unless there is a Withdrawal Bundle in this block.
    //
    // Don't add too many refunds.
    //
    if (!fCreatedWithdrawalBundle) {
        uint64_t nRefundAdded = 0;
        for (const CTxMemPool::txiter& it : vRefund) {
            CTransactionRef tx = it->GetSharedTx();
            if (tx == nullptr) continue;

            // Find the refund script
            uint256 id;
            id.SetNull();
            std::vector<unsigned char> vchSig;
            for (const CTxOut& o : tx->vout) {
                if (!o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                    continue;
                break;
            }
            if (id.IsNull())
                continue;

            // Verify refund request & get data
            SidechainWithdrawal withdrawal;
            if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
                LogPrintf("%s: Miner failed to verify withdrawal refund request! ID: %s\n", __func__, id.ToString());
                return nullptr;
            }

            // Try to add the refund payout output - if we cannot then remove it
            // and stop trying to process more refunds

            // Figure out how much weight the refund payout will add
            coinbaseTx.vout.push_back(CTxOut(withdrawal.amount, GetScriptForDestination(DecodeDestination(withdrawal.strRefundDestination))));
            uint64_t nCoinbaseTxSize = GetVirtualTransactionSize(CTransaction(coinbaseTx));

            nRefundAdded += nCoinbaseTxSize;
        }
    }

    // Get list of deposits from the mainchain

    std::vector<SidechainDeposit> vDeposit;

    SidechainDeposit lastDeposit;
    uint256 hashLastDeposit;
    uint32_t nBurnIndex = 0;
    bool fHaveDeposits = psidechaintree->GetLastDeposit(lastDeposit);
    if (fHaveDeposits) {
        hashLastDeposit = lastDeposit.dtx.GetHash();
        nBurnIndex = lastDeposit.nBurnIndex;
    }
    vDeposit = client.UpdateDeposits(hashLastDeposit, nBurnIndex);

    // Find new deposits
    std::vector<SidechainDeposit> vDepositNew;
    for (const SidechainDeposit& d: vDeposit) {
        // We look up the deposit using the hash of the deposit without the
        // payout amount set because we do not know the payout amount yet.
        if (!psidechaintree->HaveDepositNonAmount(d.GetID())) {
            vDepositNew.push_back(d);
        }
    }

    // Check deposit burn index
    for (const SidechainDeposit& d : vDepositNew) {
        if (d.nBurnIndex >= d.dtx.vout.size()) {
            LogPrintf("%s: Error: new deposit has invalid burn index:\n%s\n", __func__, d.ToString());
            return nullptr;
        }
    }

    // Sort the deposits into CTIP UTXO spend order
    std::vector<SidechainDeposit> vDepositSorted;
    if (!SortDeposits(vDepositNew, vDepositSorted)) {
        LogPrintf("%s: Error: Failed to sort deposits!\n", __func__);
        return nullptr;
    }

    // Create deposit payout output(s)
    //
    // Make sure we don't add too many deposit outputs
    //
    uint64_t nAddedSize = 0;
    CAmount nFeesAdded = CAmount(0);
    // A vector of vectors of CTxOut - each vector of CTxOut contains all of the
    // outputs for one deposit. When adding / removing deposits of the coinbase
    // transaction we have to add or remove all of the outputs for a deposit.
    std::vector<std::vector<CTxOut>> vOutPackages;

    //
    // Create the deposit payout outputs for deposits.
    //
    // - First deposit in the list should have spent the sidechain CTIP that
    // the sidechain already knows about (in db) if one exists.
    //
    // - Set the payout amount by subtracting the previous CTIP from the next.
    //
    // - Create and return a vector of vectors where each sub vector is the list
    // of outputs required to payout a deposit correctly. We keep the outputs
    // for each deposit contained in their own vector instead of combining them
    // all because we must include all of the outputs for a deposit payout to
    // be valid and if we run out of space we need to know which outputs to
    // remove without invalidating a deposit.

    // Look up CTIP spent by first new deposit and calculate payout
    if (fHaveDeposits && vDepositSorted.size()) {
        bool fFound = false;
        const SidechainDeposit& first = vDepositSorted.front();
        for (const CTxIn& in : first.dtx.vin) {
            if (in.prevout.hash == lastDeposit.dtx.GetHash()
                    && lastDeposit.dtx.vout.size() > in.prevout.n
                    && lastDeposit.nBurnIndex == in.prevout.n) {
                // Calculate payout amount
                CAmount ctipAmount = lastDeposit.dtx.vout[lastDeposit.nBurnIndex].nValue;
                if (first.amtUserPayout > ctipAmount)
                    vDepositSorted.front().amtUserPayout -= ctipAmount;
                else
                    vDepositSorted.front().amtUserPayout = CAmount(0);

                fFound = true;
                break;
            }
        }
        if (!fFound) {
            LogPrintf("%s: Error: No CTIP found for first deposit in sorted list: %s (mainchain txid)\n", __func__, first.dtx.GetHash().ToString());
            return nullptr;
        }
    }
    else
    if (!fHaveDeposits && vDepositSorted.size())
    {
        // This is the very first deposit for this sidechain so we don't need
        // to look up the CTIP that it spent
        LogPrintf("%s: The sidechain has received its first deposit!\n", __func__);
    }

    // Now that we have the value for the known CTIP that was spent for the
    // first deposit in the sorted list and have calculated the payout amount
    // for that deposit we can calculate the payout amount for the rest of the
    // deposits in the list.
    //
    // Calculate payout for remaining deposits
    if (vDepositSorted.size() > 1) {
        std::vector<SidechainDeposit>::iterator it = vDepositSorted.begin() + 1;
        for (; it != vDepositSorted.end(); it++) {
            // Points to the previous deposit in the sorted list
            std::vector<SidechainDeposit>::iterator itPrev = it - 1;

            // Find the output (ctip) this deposit spend and subract it from
            // the user payout amount. Note that we've already sorted by CTIP so
            // they all should exist but we are going to double check anyways.
            bool fFound = false;
            for (const CTxIn& in : it->dtx.vin) {
                if (in.prevout.hash == itPrev->dtx.GetHash()
                        && itPrev->dtx.vout.size() > in.prevout.n
                        && itPrev->nBurnIndex == in.prevout.n) {
                    // Calculate payout amount
                    CAmount ctipAmount = itPrev->dtx.vout[itPrev->nBurnIndex].nValue;

                    if (it->amtUserPayout > ctipAmount)
                        it->amtUserPayout -= ctipAmount;
                    else
                        it->amtUserPayout = CAmount(0);

                    fFound = true;
                    break;
                }
            }
            if (!fFound) {
                LogPrintf("%s: Error: Failed to calculate payout amount - no CTIP found for deposit: %s (mainchain txid)\n", __func__, it->dtx.GetHash().ToString());
                return nullptr;
            }
        }
    }

    // Create the deposit outputs.
    // We will loop through the sorted list of new deposits, double check a few
    // things, and then create an output paying the deposit to the destination
    // string if possible. We will also add an OP_RETURN output with the
    // serialization of the SidechainDeposit object.
    for (const SidechainDeposit& deposit : vDepositSorted) {
        // Outputs created to payout this deposit - to be added to vOutPackages
        std::vector<CTxOut> vOut;

        // Special case for Withdrawal Bundle change return. We don't pay anyone this deposit
        // but it still must be added to the database.
        if (deposit.strDest == SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST) {
            vOut.push_back(CTxOut(0, deposit.GetScript()));
            // Add this deposits output to the vector of deposit outputs
            vOutPackages.push_back(vOut);
            continue;
        }

        // Payout deposit
        if (deposit.amtUserPayout > SIDECHAIN_DEPOSIT_FEE) {
            CTxDestination dest = DecodeDestination(deposit.strDest);
            if (IsValidDestination(dest)) {
                CTxOut depositOut(deposit.amtUserPayout - SIDECHAIN_DEPOSIT_FEE, GetScriptForDestination(dest));
                vOut.push_back(depositOut);
            }
        }

        // Add serialization of deposit
        vOut.push_back(CTxOut(0, deposit.GetScript()));

        // Add this deposits outputs to the vector of deposit outputs
        vOutPackages.push_back(vOut);
    }

    LogPrintf("%s: Created deposit outputs for: %u deposits!\n", __func__, vOutPackages.size());

    for (const auto& v : vOutPackages) {
        // Add all of the outputs for this deposit to the coinbase tx
        for (const CTxOut& o : v)
            coinbaseTx.vout.push_back(o);

        // If this deposit has a payout output, it had to pay a fee
        if (v.size() > 1)
            nFeesAdded += SIDECHAIN_DEPOSIT_FEE;

        // Check the block size now & remove this deposit if the block size
        // became too large.
        uint64_t nSize = GetVirtualTransactionSize(CTransaction(coinbaseTx));
        if (nAddedSize + nSize + nBlockWeight > MAX_BLOCK_WEIGHT) {
            for (size_t i = 0; i < v.size(); i++) {
                coinbaseTx.vout.pop_back();
            }
            if (v.size() > 1)
                nFeesAdded -= SIDECHAIN_DEPOSIT_FEE;
            break;
        }

        nAddedSize += nSize;
    }
    nFees += nFeesAdded;

    coinbaseTx.vout[0].nValue = nFees;

    if (nFeesOut)
        *nFeesOut = nFees;

    // Signal the most recent Withdrawal Bundle created by this sidechain
    if (!hashCurrentWithdrawalBundle.IsNull())
        pblock->hashWithdrawalBundle = hashCurrentWithdrawalBundle;

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    pblocktemplate->vTxFees[0] = -nFees;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    BlockValidationState state;
    if (m_options.test_block_validity && !TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                                                  GetAdjustedTime, /*fCheckMerkleRoot=*/false, /*fCheckBMM=*/false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    const auto time_2{SteadyClock::now()};

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package) const
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();

    // If we are adding a refund, also account for the payout coinbase output
    if (iter->IsWithdrawalRefund()) {
        nBlockWeight += nRefundOutputSize;
    }

    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(const CTxMemPool& mempool, int& nPackagesSelected, int& nDescendantsUpdated, std::vector<CTxMemPool::txiter>& vRefund, bool fIncludeRefunds)
{
    AssertLockHeld(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    std::set<uint256> setRefund;
    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        // Skip refunds if we don't want to include them
        if (!fIncludeRefunds && mi->IsWithdrawalRefund()) {
            ++mi;
            continue;
        }

        // Very refund in the mempool again before adding it to a block
        if (mi->IsWithdrawalRefund()) {
            CTransactionRef tx = mi->GetSharedTx();
            if (tx == nullptr) {
                ++mi;
                continue;
            }

            // Find the refund script
            uint256 id;
            id.SetNull();
            std::vector<unsigned char> vchSig;
            for (const CTxOut& o : tx->vout) {
                if (!o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                    continue;
                break;
            }
            if (id.IsNull())
                continue;

            // Double check that we haven't already added another refund request
            // txn for this same withdrawal ID (that would be invalid).
            if (setRefund.count(id)) {
                LogPrintf("%s: Invalid (duplicate withdrawal ID) refund in mempool!\n", __func__);
                continue;
            }

            SidechainWithdrawal withdrawal;
            if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
                ++mi;
                continue;
            }
        }

        // First try to find a new transaction in mapTx to evaluate.
        //
        // Skip entries in mapTx that are already in a block or are present
        // in mapModifiedTx (which implies that the mapTx ancestor state is
        // stale due to ancestor inclusion in the block)
        // Also skip transactions that we've already failed to add. This can happen if
        // we consider a transaction in mapModifiedTx and it fails: we can then
        // potentially consider it again while walking mapTx.  It's currently
        // guaranteed to fail again, but as a belt-and-suspenders check we put it in
        // failedTx and avoid re-evaluation, since the re-evaluation would be using
        // cached size/sigops/fee values that are not actually correct.
        /** Return true if given transaction from mapTx has already been evaluated,
         * or if the transaction's cached data in mapTx is incorrect. */
        if (mi != mempool.mapTx.get<ancestor_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it)) {
                ++mi;
                continue;
            }
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();

        // Add the size of the refund payout that will be added to the coinbase
        if (iter->IsWithdrawalRefund()) {
            packageSize += nRefundOutputSize;
        }

        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < m_options.blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    m_options.nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            // Keep track of withdrawal refunds that are added
            if (sortedEntries[i]->IsWithdrawalRefund()) {
                vRefund.push_back(sortedEntries[i]);
            }

            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
}

bool BlockAssembler::GenerateBMMBlock(const CScript& scriptPubKey, CBlock& block, std::string& strError, CAmount* nFeesOut, const uint256& hashPrevBlock)
{
    // Either generate a new scriptPubKey or use the one that has optionally
    // been passed in
    if (scriptPubKey.empty()) {
        strError = "scriptPubKey required!\n";
        return false;
    }

    std::unique_ptr<CBlockTemplate> pblocktemplate;
    pblocktemplate = BlockAssembler(m_chainstate, m_mempool).CreateNewBlock(scriptPubKey, hashPrevBlock, nFeesOut);

    if (!pblocktemplate.get()) {
        strError = "Failed to get block template!\n";
        return false;
    }
    const CBlockIndex* prev_block;
    LOCK(cs_main);
    {
        prev_block = m_chainstate.m_chainman.m_blockman.LookupBlockIndex(pblocktemplate->block.hashPrevBlock);
    }
    if (!prev_block) {
        strError = "Invalid hashPrevBlock!\n";
        return false;
    }

    block = pblocktemplate->block;

    return true;
}
} // namespace node
