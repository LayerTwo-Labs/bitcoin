// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <dbwrapper.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <random.h>
#include <shutdown.h>
#include <sidechain.h>
#include <uint256.h>
#include <util/vector.h>

#include <cassert>
#include <cstdlib>
#include <iterator>
#include <utility>
#include <node/chainstatemanager_args.h>
#include <util/system.h>
#include <streams.h>
#include <validation.h>

#include <stdint.h>

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
static constexpr uint8_t DB_FLAG{'F'};
static constexpr uint8_t DB_REINDEX_FLAG{'R'};
static constexpr uint8_t DB_LAST_BLOCK{'l'};

static const char DB_LAST_SIDECHAIN_DEPOSIT = 'x';
static const char DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE = 'w';

// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};

bool CCoinsViewDB::NeedsUpgrade()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    return cursor->Valid();
}

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

} // namespace

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return m_db->Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock, bool erase) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent())
                batch.Erase(entry);
            else
                batch.Write(entry, it->second.coin);
            changed++;
        }
        count++;
        it = erase ? mapCoins.erase(it) : std::next(it);
        if (batch.SizeEstimate() > m_options.batch_write_bytes) {
            LogPrint(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            m_db->WriteBatch(batch);
            batch.Clear();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? uint8_t{'1'} : uint8_t{'0'});
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    uint8_t ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == uint8_t{'1'};
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&, const uint256&)> insertBlockIndex)
{
    AssertLockHeld(::cs_main);
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    // Load m_block_index
    while (pcursor->Valid()) {
        if (ShutdownRequested()) return false;
        std::pair<uint8_t, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.ConstructBlockHash(), diskindex.hashMainchainBlock);
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev, diskindex.hashMainchainBlock);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->hashWithdrawalBundle = diskindex.hashWithdrawalBundle;
                pindexNew->hashMainchainBlock = diskindex.hashMainchainBlock;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    return true;
}

CSidechainTreeDB::CSidechainTreeDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(DBParams{
            .path = gArgs.GetDataDirNet() / "sidechain",
            .cache_bytes = nCacheSize,
            .memory_only = fMemory,
            .wipe_data = fWipe}) {};


bool CSidechainTreeDB::WriteSidechainIndex(const std::vector<std::pair<uint256, const SidechainObj *> > &list)
{
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256, const SidechainObj *> >::const_iterator it=list.begin(); it!=list.end(); it++) {
        const uint256 &objid = it->first;
        const SidechainObj *obj = it->second;
        std::pair<char, uint256> key = std::make_pair(obj->sidechainop, objid);

        if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP) {
            const SidechainWithdrawal *ptr = (const SidechainWithdrawal *) obj;
            batch.Write(key, *ptr);
        }
        else
        if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
            const SidechainWithdrawalBundle *ptr = (const SidechainWithdrawalBundle *) obj;
            batch.Write(key, *ptr);

            // Also index the WithdrawalBundle by the WithdrawalBundle transaction hash
            uint256 hashWithdrawalBundle = ptr->tx.GetHash();
            std::pair<char, uint256> keyTx = std::make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle);
            batch.Write(keyTx, *ptr);

            // Update DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE
            batch.Write(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hashWithdrawalBundle);

            LogPrintf("%s: Writing new WithdrawalBundle and updating DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE to: %s",
                    __func__, hashWithdrawalBundle.ToString());
        }
        else
        if (obj->sidechainop == DB_SIDECHAIN_DEPOSIT_OP) {
            const SidechainDeposit *ptr = (const SidechainDeposit *) obj;
            batch.Write(key, *ptr);

            // Also index the deposit by the non amount hash
            uint256 hashNonAmount = ptr->GetID();
            batch.Write(std::make_pair(DB_SIDECHAIN_DEPOSIT_OP, hashNonAmount), *ptr);

            // Update DB_LAST_SIDECHAIN_DEPOSIT
            batch.Write(DB_LAST_SIDECHAIN_DEPOSIT, hashNonAmount);
        }
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteWithdrawalUpdate(const std::vector<SidechainWithdrawal>& vWithdrawal)
{
    CDBBatch batch(*this);

    for (const SidechainWithdrawal& wt : vWithdrawal)
    {
        std::pair<char, uint256> key = std::make_pair(wt.sidechainop, wt.GetID());
        batch.Write(key, wt);
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteWithdrawalBundleUpdate(const SidechainWithdrawalBundle& withdrawalBundle)
{
    CDBBatch batch(*this);

    std::pair<char, uint256> key = std::make_pair(withdrawalBundle.sidechainop, withdrawalBundle.GetID());
    batch.Write(key, withdrawalBundle);

    // Also index the WithdrawalBundle by the WithdrawalBundle transaction hash
    uint256 hashWithdrawalBundle = withdrawalBundle.tx.GetHash();
    std::pair<char, uint256> keyTx = std::make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle);
    batch.Write(keyTx, withdrawalBundle);

    // Also write withdrawal status updates if WithdrawalBundle status changes
    std::vector<SidechainWithdrawal> vUpdate;
    for (const uint256& id: withdrawalBundle.vWithdrawalID) {
        SidechainWithdrawal withdrawal;
        if (!GetWithdrawal(id, withdrawal)) {
            LogPrintf("%s: Failed to read withdrawal of WithdrawalBundle from LDB!\n", __func__);
            return false;
        }
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_FAILED) {
            withdrawal.status = WITHDRAWAL_UNSPENT;
            vUpdate.push_back(withdrawal);
        }
        else
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_SPENT) {
            withdrawal.status = WITHDRAWAL_SPENT;
            vUpdate.push_back(withdrawal);
        }
        else
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_CREATED) {
            withdrawal.status = WITHDRAWAL_IN_BUNDLE;
            vUpdate.push_back(withdrawal);
        }
    }

    if (!WriteWithdrawalUpdate(vUpdate)) {
        LogPrintf("%s: Failed to write withdrawal update!\n", __func__);
        return false;
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteLastWithdrawalBundleHash(const uint256& hash)
{
    return Write(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hash);
}

bool CSidechainTreeDB::GetWithdrawal(const uint256& objid, SidechainWithdrawal& withdrawal)
{
    if (Read(std::make_pair(DB_SIDECHAIN_WITHDRAWAL_OP, objid), withdrawal))
        return true;

    return false;
}

bool CSidechainTreeDB::GetWithdrawalBundle(const uint256& objid, SidechainWithdrawalBundle& withdrawalBundle)
{
    if (Read(std::make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, objid), withdrawalBundle))
        return true;

    return false;
}

bool CSidechainTreeDB::GetDeposit(const uint256& objid, SidechainDeposit& deposit)
{
    if (Read(std::make_pair(DB_SIDECHAIN_DEPOSIT_OP, objid), deposit))
        return true;

    return false;
}

std::vector<SidechainWithdrawal> CSidechainTreeDB::GetWithdrawals(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_WITHDRAWAL_OP;
    DataStream ss;
    ::Serialize(ss, std::make_pair(std::make_pair(sidechainop, nSidechain), uint256()));

    std::vector<SidechainWithdrawal> vWT;

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        if (ShutdownRequested()) return std::vector<SidechainWithdrawal>{};

        std::pair<char, uint256> key;
        SidechainWithdrawal wt;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetValue(wt))
                vWT.push_back(wt);
        }

        pcursor->Next();
    }

    return vWT;
}

std::vector<SidechainWithdrawalBundle> CSidechainTreeDB::GetWithdrawalBundles(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP;
    DataStream ss;
    ::Serialize(ss, std::make_pair(std::make_pair(sidechainop, nSidechain), uint256()));

    std::vector<SidechainWithdrawalBundle> vWithdrawalBundle;

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        if (ShutdownRequested()) return std::vector<SidechainWithdrawalBundle>{};

        std::pair<char, uint256> key;
        SidechainWithdrawalBundle withdrawalBundle;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetValue(withdrawalBundle)) {
                // Only return the WithdrawalBundle(s) indexed by ID
                if (key.second == withdrawalBundle.GetID())
                    vWithdrawalBundle.push_back(withdrawalBundle);
            }
        }

        pcursor->Next();
    }
    return vWithdrawalBundle;
}

std::vector<SidechainDeposit> CSidechainTreeDB::GetDeposits(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_DEPOSIT_OP;
    DataStream ss;
    ::Serialize(ss, std::make_pair(std::make_pair(sidechainop, nSidechain), uint256()));

    std::vector<SidechainDeposit> vDeposit;

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        if (ShutdownRequested()) return std::vector<SidechainDeposit>{};

        std::pair<char, uint256> key;
        SidechainDeposit deposit;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetValue(deposit))
                // Only return the deposits(s) indexed by ID
                if (key.second == deposit.GetID())
                    vDeposit.push_back(deposit);
        }

        pcursor->Next();
    }
    return vDeposit;
}

bool CSidechainTreeDB::HaveDeposits()
{
    const char sidechainop = DB_SIDECHAIN_DEPOSIT_OP;
    DataStream ss;
    ::Serialize(ss, std::make_pair(std::make_pair(sidechainop, DB_SIDECHAIN_DEPOSIT_OP), uint256()));

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    if (pcursor->Valid()) {
        if (ShutdownRequested()) return false;

        std::pair<char, uint256> key;
        SidechainDeposit d;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetValue(d))
                return true;
        }
    }
    return false;
}

bool CSidechainTreeDB::HaveDepositNonAmount(const uint256& hashNonAmount)
{
    SidechainDeposit deposit;
    if (Read(std::make_pair(DB_SIDECHAIN_DEPOSIT_OP, hashNonAmount),
                deposit))
        return true;

    return false;
}

bool CSidechainTreeDB::GetLastDeposit(SidechainDeposit& deposit)
{
    // Look up the last deposit non amount hash
    uint256 objid;
    if (!Read(DB_LAST_SIDECHAIN_DEPOSIT, objid))
        return false;

    // Read the last deposit
    if (Read(std::make_pair(DB_SIDECHAIN_DEPOSIT_OP, objid), deposit))
        return true;

    return false;
}

bool CSidechainTreeDB::GetLastWithdrawalBundleHash(uint256& hash)
{
    // Look up the last deposit non amount hash
    if (!Read(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hash))
        return false;

    return true;
}

bool CSidechainTreeDB::HaveWithdrawalBundle(const uint256& hashWithdrawalBundle) const
{
    SidechainWithdrawalBundle withdrawalBundle;
    if (Read(std::make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle), withdrawalBundle))
        return true;

    return false;
}
