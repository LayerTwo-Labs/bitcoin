#ifndef BITCOIN_BMMCACHE_H
#define BITCOIN_BMMCACHE_H

#include "uint256.h"

#include <deque>
#include <map>
#include <set>
#include <vector>

class CBlock;

struct MainBlockIndex
{
    size_t index;
    uint256 hash;
};

class BMMCache
{
public:
    BMMCache();

    bool StoreBMMBlock(const CBlock& block);

    bool GetBMMBlock(const uint256& hashMerkleRoot, CBlock& block);

    std::vector<CBlock> GetBMMBlockCache() const;

    std::vector<uint256> GetBroadcastedWithdrawalBundleCache() const;

    std::vector<uint256> GetMainBlockHashCache() const;

    std::vector<uint256> GetRecentMainBlockHashes() const;

    void ClearBMMBlocks();

    void StoreBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle);

    void StorePrevBlockBMMCreated(const uint256& hashPrevBlock);

    bool HaveBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle) const;

    // Check if we already verified BMM for this sidechain block
    bool HaveVerifiedBMM(const uint256& hashBlock) const;

    // Cache that we verified BMM for this sidechain block
    void CacheVerifiedBMM(const uint256& hashBlock);

    // Check if we already verified deposit
    bool HaveVerifiedDeposit(const uint256& txid) const;

    // Cache that we verified a deposit with the mainchain
    void CacheVerifiedDeposit(const uint256& txid);

    std::vector<uint256> GetVerifiedBMMCache() const;

    std::vector<uint256> GetVerifiedDepositCache() const;

    void CacheMainBlockHash(const uint256& hash);

    void CacheMainBlockHash(const std::vector<uint256>& vHash);

    bool UpdateMainBlockCache(std::deque<uint256>& deqHashNew, bool& fReorg, std::vector<uint256>& vOrphan);

    uint256 GetLastMainBlockHash() const;

    uint256 GetMainPrevBlockHash(const uint256& hashBlock) const;

    int GetCachedBlockCount() const;

    int GetMainchainBlockHeight(const uint256& hash) const;

    bool HaveMainBlock(const uint256& hash) const;

    bool HaveBMMRequestForPrevBlock(const uint256& hashPrevBlock) const;

    void AddCheckedMainBlock(const uint256& hashBlock);

    bool MainBlockChecked(const uint256& hashMainBlock) const;

    void ResetMainBlockCache();

    void CacheWithdrawalID(const uint256& wtid);

    std::set<uint256> GetCachedWithdrawalID();

    bool IsMyWT(const uint256& wtid);

private:
    // BMM blocks that we have created with the intention of connecting to the
    // side blockchain once the BMM h* hash is included on the mainchain
    std::map<uint256 /* hashMerkleRoot */, CBlock> mapBMMBlocks;

    // Cache of sidechain block hashes which we have already verified with the
    // mainchain as having the BMM h* hash included.
    std::set<uint256 /* hashBlock */> setBMMVerified;

    // Cache of deposit txid which we have already verified with the mainchain
    std::set<uint256 /* txid */> setDepositVerified;

    // WithdrawalBundle(s) that we have already broadcasted to the mainchain.
    std::set<uint256> setWithdrawalBundleBroadcasted;

    // Index of mainchain block hash in vMainBlockHash
    std::map<uint256 /* hashMainchainBlock */, MainBlockIndex> mapMainBlock;

    // List of all known mainchain block hashes in order
    std::vector<uint256> vMainBlockHash;

    // TODO we could also cache a map of mainchain block hashes that we created
    // BMM requests for. That way, to check for BMM commitments we can just
    // check recent blocks that we created a commitment for instead of scanning
    // all of them.
    //
    // Set of hashes for which we've created a BMM request with this mainchain
    // prevblock. (Meaning the BMM request was created when the hash was the
    // mainchain tip)
    std::set<uint256> setPrevBlockBMMCreated;

    // Set of main block hashes that we've already checked for our BMM requests
    std::set<uint256> setMainBlockChecked;

    // WithdrawalIDs for WT(s) created by the user
    std::set<uint256> setWITHDRAWALIDCache;
};

#endif // BITCOIN_BMMCACHE_H
