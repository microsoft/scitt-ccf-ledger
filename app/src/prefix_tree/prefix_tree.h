// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "prefix_tree/bitvector.h"

#include <array>
#include <ccf/ccf_assert.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/ds/hex.h>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace scitt::pt
{
  /**
   * Compute the hash of an intermediate node.
   *
   * This is defined as sha256(prefix || left_hash || right_hash), where prefix
   * is padded to the size of the tree's index.
   *
   * The prefix tree can be configured to use a different hash function for the
   * nodes, but this implementation suffices for any application using SHA256.
   */
  template <size_t SIZE>
  crypto::Sha256Hash hash_node(
    const pt::bitprefix<SIZE>& prefix,
    const crypto::Sha256Hash& left,
    const crypto::Sha256Hash& right)
  {
    auto h = crypto::make_incremental_sha256();
    h->update_hash(prefix.data());
    h->update_hash(left.h);
    h->update_hash(right.h);
    return h->finalise();
  }

  template <size_t SIZE, typename HashT>
  using hash_node_t =
    HashT (*)(const bitprefix<SIZE>&, const HashT&, const HashT&);

  /**
   * A leaf of the prefix tree.
   *
   * Each leaf has an index, a value and a hash. The index is used to look up
   * the leaf in the tree; for a given index, the tree will contain at most a
   * single leaf.
   *
   * For performance and protection against DoS, indices must be uniformly
   * distributed, and not under attacker control. Typically, the index will be a
   * cryptographic hash of the lookup key.
   *
   * It is the application's reponsibility to compute the leaf's hash before
   * adding it to the prefix tree. This allows the leaf's hash to bind over more
   * data than is present in the leaf. The leaf's hash must cover its index.
   * Whether or not it covers the value is application-specific.
   */
  template <
    typename ValueT,
    typename HashT = crypto::Sha256Hash,
    size_t SIZE = 32>
  struct leaf
  {
    bitvector<SIZE> index;
    ValueT value;
    HashT hash;
  };

  template <
    typename HashT = crypto::Sha256Hash,
    size_t SIZE = 32,
    hash_node_t<SIZE, HashT> HASH_NODE = hash_node<SIZE>>
  struct path
  {
    bitvector<SIZE> prefixes;
    std::vector<HashT> hashes;

    HashT hash(const bitvector<SIZE>& index, HashT hash)
    {
      size_t i = 0;
      for (size_t j = prefixes.size(); j > 0; j--)
      {
        if (prefixes.bit(j - 1))
        {
          auto prefix = index.first(j - 1);
          bool bit = index.bit(j - 1);
          if (bit)
          {
            hash = HASH_NODE(prefix, hashes.at(hashes.size() - i - 1), hash);
          }
          else
          {
            hash = HASH_NODE(prefix, hash, hashes.at(hashes.size() - i - 1));
          }
          i++;
        }
      }
      return hash;
    }

    /**
     * Get an implementation-specific but structured representation of this
     * path. This should be used for debugging purposes, and should not be
     * parsed as the format is subject to change.
     */
    nlohmann::json debug() const
    {
      nlohmann::json result;
      result["prefixes"] = prefixes.bitstring();
      result["proof"] = hashes;
      return result;
    }
  };

  /**
   * A prefix tree maps keys to values, providing cryptographic inclusion proof
   * for each entry.
   *
   * Each leaf is a key/value assignment, and gets hashed to produce a digest.
   * The digests of all the leaves are combined to form a Merkle tree. It is
   * possible to prove the inclusion of a given entry by providing the hashes of
   * sibling nodes in the tree. The number of hashes is equal to the height of
   * the tree, or O(log(n)) given n leaves with uniformly distributed keys.
   *
   * When a leaf is inserted or modified, only the hashes of intermediate nodes
   * from the root to the updated leaf need to be computed, roughly O(log(n)).
   * If many leaves need to be updated at once, a batch update can be performed
   * to avoid unnecessary repeated updates to the common intermediate nodes.
   *
   * This class requires keys to be a bitvector of a configurable size.
   * Typically this bitvector would be the cryptographic hash of a more complex
   * key, such as a string.
   */
  template <
    typename ValueT,
    typename HashT = crypto::Sha256Hash,
    size_t SIZE = 32,
    hash_node_t<SIZE, HashT> HASH_NODE = hash_node<SIZE>>
  struct prefix_tree
  {
    typedef leaf<ValueT, HashT, SIZE> leaf_t;
    typedef path<HashT, SIZE, HASH_NODE> path_t;

    struct inserter;
    struct prospective_inserter;
    struct navigator;
    struct stream;

  private:
    typedef std::unique_ptr<leaf_t> leaf_ptr;

    struct node
    {
      node(bitprefix<SIZE> prefix) : prefix(prefix) {}

      bitprefix<SIZE> prefix;

      // TODO: use pointer alignment bits to tag this instead of an
      // std::variant.
      std::variant<leaf_ptr, std::unique_ptr<node>> children[2];

      HashT hash;

      void rehash()
      {
        hash = HASH_NODE(
          prefix,
          prefix_tree::hash(children[0]),
          prefix_tree::hash(children[1]));
      }
    };

    typedef std::unique_ptr<node> node_ptr;
    typedef std::variant<leaf_ptr, node_ptr> position;

  public:
    /**
     * Insert an single leaf into the tree. Hashes within the tree are updated
     * to reflect the new leaf.
     *
     * If a leaf with the same index already exists, its value is updated.
     */
    void insert(leaf_t l)
    {
      if (root_.has_value())
      {
        insert(&root_.value(), l);
      }
      else
      {
        root_ = std::make_unique<leaf_t>(l);
      }
    }

    /**
     * Add a batch of leaves into the tree.
     *
     * This is equivalent to calling `insert` with each leaf, but avoids
     * repeated computation of intermediate nodes. The list of leaves must be
     * ordered by index (repeated indices are allowed).
     */
    void insert(std::span<const leaf_t> ls)
    {
      auto i = start_insert();
      for (const auto& l : ls)
      {
        i.add(l);
      }
      i.finish();
    }

    /**
     * Create an inserter, allowing a batch of leaves to be added to the tree.
     *
     * Leaves must be passed to the inserter in increasing index order, and the
     * `finish` method must be called on the inserter to complete the operation.
     *
     * Until `finish` is called, the tree may be in an inconsistent state.
     */
    inserter start_insert()
    {
      return inserter(&root_);
    }

    /**
     * Get the hash of the root of the tree.
     *
     * If the tree is empty, a default constructed `HashT` is returned.
     */
    HashT hash() const
    {
      if (root_.has_value())
      {
        return hash(root_.value());
      }
      else
      {
        return {};
      }
    }

    /**
     * Search for a given index inside the tree.
     *
     * If a leaf with this index is found, a reference to its value is returned,
     * along with an inclusion proof connecting the leaf to the root of the
     * tree.
     *
     * Assuming `find` returns a value, the following property holds:
     * ```
     * auto [path, value] = *tree.find(index);
     * assert(path.hash(index, value) == tree.hash());
     * ```
     *
     * The search works by iterating over each bit of the index, comparing it
     * with the current code in the tree.If we exhaust all the bit of the
     * current intermediate node, then we follow the appropriate child and
     * record the sibling's hash for the inclusion proof.
     *
     * If at any point the bits of the index differ with the node we are looking
     * at, then the index is not present in the tree and std::nullopt is
     * returned.
     */
    std::optional<std::pair<path_t, std::reference_wrapper<const ValueT>>> find(
      const bitvector<SIZE>& index) const
    {
      if (!root_.has_value())
      {
        return std::nullopt;
      }

      path_t result;

      const position* p = &root_.value();
      bitslice<SIZE> prefix = get_prefix(*p);

      for (size_t i = 0; i < 8 * SIZE; i++)
      {
        bool b = index.bit(i);
        if (i == prefix.size())
        {
          const auto& node = std::get<node_ptr>(*p);
          result.prefixes.set_bit(i, 1);
          result.hashes.push_back(hash(node->children[1 - b]));

          p = &node->children[b];
          prefix = get_prefix(*p);
        }
        else if (prefix.bit(i) != b)
        {
          return std::nullopt;
        }
      }

      const auto& leaf = std::get<leaf_ptr>(*p);
      CCF_ASSERT_FMT(
        leaf->index == index,
        "invalid leaf index: {} vs {}",
        ds::to_hex(leaf->index.data()),
        ds::to_hex(index.data()));
      return {{result, std::get<leaf_ptr>(*p)->value}};
    }

    /**
     * Create a prospective inserter from the tree.
     *
     * This makes it possible to compute what the hash of the root would be if a
     * batch of new leaves were added to the tree. The actual tree is not
     * modified.
     */
    prospective_inserter prospective_insert() const
    {
      return prospective_inserter(root_);
    }

    /**
     * Get an implementation-specific but structured representation of this
     * tree. This should be used for debugging purposes, and should not be
     * parsed as the format is subject to change.
     */
    nlohmann::json debug() const
    {
      if (root_.has_value())
      {
        return debug(root_.value());
      }
      else
      {
        return nlohmann::json();
      }
    }

  private:
    static HashT hash(const position& p)
    {
      if (std::holds_alternative<leaf_ptr>(p))
      {
        const auto& leaf = std::get<leaf_ptr>(p);
        return leaf->hash;
      }
      else
      {
        const auto& node = std::get<node_ptr>(p);
        return node->hash;
      }
    }

    static nlohmann::json debug(const position& p)
    {
      nlohmann::json result;
      result["hash"] = hash(p);
      if (std::holds_alternative<leaf_ptr>(p))
      {
        const auto& leaf = std::get<leaf_ptr>(p);
        result["index"] = leaf->index.bitstring();
        result["value"] = leaf->value;
      }
      else
      {
        const auto& node = std::get<node_ptr>(p);
        result["prefix"] = node->prefix.bitstring();
        result["left"] = debug(node->children[0]);
        result["right"] = debug(node->children[1]);
      }
      return result;
    }

    static bitslice<SIZE> get_prefix(const position& p)
    {
      if (std::holds_alternative<leaf_ptr>(p))
      {
        return std::get<leaf_ptr>(p)->index;
      }
      else
      {
        return std::get<node_ptr>(p)->prefix;
      }
    }

    /**
     * This is the core tree insertion algorithm.
     *
     * It iterates over the bits of the index of `l`, comparing the bits one by
     * one with the contents of the tree. At any given moment, the function is
     * focused on one node `p`, whose first `depth` bits match the leaf being
     * inserted.
     *
     * For each bit, the following cases are possible:
     * - `p` is an intermediate node, and we've exhausted all of its bits.
     *   We focus on one of its children, based on the bit value of `l`.
     * - `p` and `l` share the same bit value. We can move to the next bit.
     * - `p` and `l` have a different bit value. We insert a new intermediate
     *   node to represent the fork, where `p` and `l` are the new node's two
     *   children. The new node replaces `p` in the current tree.
     *
     * If all of `p` and `l`'s bits match, then we are updating an existing leaf
     * rather inserting a new one.
     *
     * When we've reached the end and have inserted/updated the node as
     * appropriate, we need to update the hashes of every intermediate node from
     * the root to the new leaf. We do so by keeping track of these in a vector
     * as we descend the tree, and rehash each node in reverse order afterwards.
     */
    void insert(position* p, leaf_t l)
    {
      std::vector<node*> recompute;
      bitslice<SIZE> prefix = get_prefix(*p);
      size_t depth = 0;
      for (; depth < 8 * SIZE; depth++)
      {
        bool b = l.index.bit(depth);
        if (depth == prefix.size())
        {
          auto& node = std::get<node_ptr>(*p);
          recompute.push_back(node.get());
          p = &node->children[b];
          prefix = get_prefix(*p);
        }
        else if (prefix.bit(depth) != b)
        {
          auto fresh = std::make_unique<node>(prefix.first(depth));
          fresh->children[b] = std::make_unique<leaf_t>(l);
          fresh->children[1 - b] = std::move(*p);
          recompute.push_back(fresh.get());
          *p = std::move(fresh);
          break;
        }
      }

      // We have an exact match on the full index.
      // Update the value and hash of the leaf.
      if (depth == 8 * SIZE)
      {
        auto& found = std::get<leaf_ptr>(*p);
        CCF_ASSERT_FMT(
          found->index == l.index,
          "invalid leaf index: {} vs {}",
          ds::to_hex(found->index.data()),
          ds::to_hex(l.index.data()));
        *found = l;
      }

      // It's important that we do this in reverse order, as the hashes deep
      // inside the tree affect the ones at the top.
      for (auto it = recompute.rbegin(); it != recompute.rend(); it++)
      {
        (*it)->rehash();
      }
    }

  public:
    std::optional<position> root_;
  };

  template <
    typename ValueT,
    typename HashT,
    size_t SIZE,
    hash_node_t<SIZE, HashT> HASH_NODE>
  struct prefix_tree<ValueT, HashT, SIZE, HASH_NODE>::inserter
  {
    std::optional<position>* root;

    // The last element in the stack is the node we compare against when
    // performing the insertion. Elements prior are its parents.
    std::vector<position*> stack;

    inserter(std::optional<position>* root) : root(root) {}

    /**
     * Add a leaf to the tree, in a batched manner.
     *
     * This algorithm is similar to the single-leaf insertion ones with the
     * following changes:
     * - Between two invocations, we keep track of our position in the tree to
     *   avoid traversing the tree down again. This includes the current node
     *   along with its parents.
     * - Before inserting a new leaf, we may need to rewind our position, based
     *   on how many bits the new leaf shares with the previous one that was
     *   inserted.
     * - When rewinding, we will be leaving intermediate nodes behind that will
     *   never be revisited (due to leaves being order by index). Their hash
     *   will be invalid due to the children node having been modified and needs
     *   to be recomputed.
     * - After the last leaf is inserted all remaining intermediate nodes need
     *   to be rehashed, effectively rewinding all the way to the top.
     */
    void add(leaf_t l)
    {
      if (!root->has_value())
      {
        *root = std::make_unique<leaf_t>(l);
        stack.push_back(&root->value());
        return;
      }

      size_t depth;
      if (stack.empty())
      {
        stack.push_back(&root->value());
        depth = 0;
      }
      else
      {
        // Between invocations of `add`, the back of the stack is always a leaf.
        auto& previous = std::get<leaf_ptr>(*stack.back());
        CCF_ASSERT_FMT(
          previous->index <= l.index,
          "leaves must be inserted in order: {} > {}",
          ds::to_hex(previous->index.data()),
          ds::to_hex(l.index.data()));

        depth = common_prefix(previous->index, l.index);
        rewind(depth);
      }

      for (; depth < SIZE * 8; depth++)
      {
        position* p = stack.back();
        bitslice<SIZE> prefix = get_prefix(*p);
        bool b = l.index.bit(depth);

        if (prefix.size() == depth)
        {
          // This is an intermediate node, and we've matched all its bits.
          // Follow the branch that matches the current leaf.
          auto& node = std::get<node_ptr>(*p);
          stack.push_back(&node->children[b]);
        }
        else if (prefix.bit(depth) != b)
        {
          // We have a mismatch on one of the bits. Insert an intermediate node,
          // record the common prefix, move the existing node as one of the
          // children and add the new leaf as the other one.
          //
          // By moving `*p` into a child of the new node, we effectively take it
          // out of the stack, which means there is no record of whether it
          // needs to be rehashed anymore. To make sure its hash is consistent,
          // we re-hash it here. If `b` is false, we are inserting to the left
          // of *p and thanks to the in-order insertion requirement we know we
          // haven't visited *p's children yet, so no need to recompute the
          // hash. There are cases where b is true and yet we never visited its
          // children so re-hashing is unnecessary, but it would take some
          // effort to track this, so this is a bit more conservative than it
          // would need to be.
          if (b && std::holds_alternative<node_ptr>(*p))
          {
            const auto& n = std::get<node_ptr>(*p);
            n->rehash();
          }

          auto fresh = std::make_unique<node>(prefix.first(depth));
          fresh->children[b] = std::make_unique<leaf_t>(l);
          fresh->children[1 - b] = std::move(*p);
          stack.push_back(&fresh->children[b]);
          *p = std::move(fresh);
          return;
        }
      }

      // We have an exact match on the full index.
      // Update the value and hash of the leaf.
      auto& found = std::get<leaf_ptr>(*stack.back());
      CCF_ASSERT_FMT(
        found->index == l.index,
        "invalid leaf index: {} vs {}",
        ds::to_hex(found->index.data()),
        ds::to_hex(l.index.data()));
      *found = l;
    }

    void finish()
    {
      while (!stack.empty())
      {
        if (node_ptr* n = std::get_if<node_ptr>(stack.back()))
        {
          (*n)->rehash();
        }
        stack.pop_back();
      }
    }

  private:
    /**
     * Rewind our position in the tree until we are at the given depth.
     *
     * All nodes in the stack but the last one must have a shorter prefix than
     * depth. Nodes that are removed from the stack will never be visited again,
     * but may have inconsistent hashes. We need to recompute it before they get
     * removed.
     */
    void rewind(size_t depth)
    {
      while (stack.size() >= 2 &&
             get_prefix(*stack[stack.size() - 2]).size() >= depth)
      {
        if (node_ptr* n = std::get_if<node_ptr>(stack.back()))
        {
          (*n)->rehash();
        }
        stack.pop_back();
      }
    }
  };

  /**
   * stream allows the computation of the root hash of a prefix tree, without
   * ever building the actual tree in memory. For a balanced tree, it only needs
   * O(log(n)) space.
   *
   * Leaves must be added to the stream in index order.
   *
   * The algorithm works by keeping a stack of hashes. The back of the stack
   * corresponds to the last leaf that was added, and all hashes before it are
   * the sibling hashes that need to be combined to form the root hash.
   *
   * Consider the following prefix tree:
   *
   *                   root
   *           0                100
   *      00      01
   *   000 001  010 011
   *
   * After 011 is added to the stream, the stack contains
   * [ H(00), H(010), H(011) ]. When adding 100 to the stream, we must first
   * "compress" the stack, first into [ H(00), H(01) ], then [ H(0) ].
   * Finally we can add H(100) to the stack, and compress again to obtain
   * H(root).
   *
   */
  template <
    typename ValueT,
    typename HashT,
    size_t SIZE,
    hash_node_t<SIZE, HashT> HASH_NODE>
  struct prefix_tree<ValueT, HashT, SIZE, HASH_NODE>::stream
  {
    void add(const leaf_t& l)
    {
      if (last_leaf.has_value())
      {
        CCF_ASSERT_FMT(
          *last_leaf <= l.index,
          "leaves must be inserted in order: {} > {}",
          ds::to_hex(last_leaf->data()),
          ds::to_hex(l.index.data()));

        size_t prefix = common_prefix(*last_leaf, l.index);

        // If we get a full match, then this is updating the previous value.
        // Rather than adding a new entry to the stack, we instead update the
        // latest hash.
        if (prefix == 8 * SIZE)
        {
          stack.back().hash = l.hash;
          return;
        }
        compress(prefix);
      }
      stack.push_back(entry{8 * SIZE, l.hash});
      last_leaf = l.index;
    }

    HashT hash()
    {
      compress(0);
      if (stack.empty())
      {
        return {};
      }
      else
      {
        return stack.at(0).hash;
      }
    }

  private:
    void compress(size_t length)
    {
      while (stack.size() >= 2 && stack[stack.size() - 2].length >= length)
      {
        entry last = stack.back();
        stack.pop_back();

        auto prefix = last_leaf->first(stack.back().length);
        stack.back().hash = HASH_NODE(prefix, stack.back().hash, last.hash);
      }

      if (!stack.empty() && stack.back().length > length)
      {
        stack.back().length = length;
      }
    }

    // Index of the last leaf we hashed.
    std::optional<bitvector<SIZE>> last_leaf;

    // Stack representing all the already-hashed leaves, ordered by
    // strictly-increasing lengths.
    struct entry
    {
      size_t length;
      HashT hash;
    };
    std::vector<entry> stack;
  };

  /**
   * The navigator is a helper algorithm used to implement the
   * prospective_inserter.
   *
   * It allows, from an existing tree, to enumerate the hashes of leaves that
   * fall within a range of indices. Leaves that share a common prefix are
   * condensed and only the hash of the intermediate node is returned.
   *
   * In practice, the navigator is used by issuing an interleaved sequence of
   * `visit` and `rewind` calls. The initial call to visit returns all hashes
   * for nodes smaller than the specified index.
   *
   * Consider the following tree:
   *
   *                   root
   *          0                   1
   *    000       01         101      11
   *           010  011            110  111
   *
   * An initial call to visit(001) would return [ H(000) ], since only this leaf
   * smaller than 001.
   *
   * In principle, a call to visit(110) would return [ H(01), H(101) ], since
   * these are the nodes that fall between 001 and 110. However, we want to
   * distinguish between hashes that appear on the right or on the left of the
   * traversal. Therefore, we first call rewind(0), where 0 is the length of the
   * shared prefix between 001 and 110. This call returns [ H(01) ], that is the
   * list of hashes encoutered on the way back to the top of the tree. Then the
   * call to visit(110) returns [ H(101) ], that is the list of hashes on the
   * way back down to the index of interest.
   *
   * Finally we may call finish(), which returns [ H(111) ], the list of hashes
   * that have not been visited.
   *
   * Note that a) indices that are visited do not need to be present in the tree
   * and b) if a visited index is present, the corresponding hash is never
   * returned by any of the calls.
   *
   */
  template <
    typename ValueT,
    typename HashT,
    size_t SIZE,
    hash_node_t<SIZE, HashT> HASH_NODE>
  struct prefix_tree<ValueT, HashT, SIZE, HASH_NODE>::navigator
  {
    struct entry
    {
      size_t length;
      HashT hash;
    };

    navigator(const std::optional<position>& root)
    {
      if (root.has_value())
      {
        const position* p = &root.value();
        stack.push_back({p, false, p});
      }
    }

    std::vector<entry> visit(const pt::bitvector<SIZE>& index)
    {
      if (stack.empty())
      {
        return {};
      }

      std::vector<entry> result;
      for (; depth < SIZE * 8; depth++)
      {
        bitslice<SIZE> prefix = get_prefix(*stack.back().p);
        bool b = index.bit(depth);
        const position* p = stack.back().p;

        if (prefix.size() == depth)
        {
          auto& node = std::get<node_ptr>(*p);
          if (!b)
          {
            stack.back().visited_left = true;
            stack.back().right = &node->children[1];
            stack.back().length = depth;
          }
          if (b)
          {
            if (!stack.back().visited_left)
            {
              result.push_back({depth, hash(node->children[0])});
            }
            stack.back().right = nullptr;
            stack.back().visited_left = true;
          }
          stack.push_back({&node->children[b]});
        }
        else if (prefix.bit(depth) != b)
        {
          if (!b)
          {
            stack.back().right = p;
            stack.back().length = depth;
          }
          if (b && !stack.back().visited_left)
          {
            result.push_back({depth, hash(*p)});
            stack.back().visited_left = true;
            stack.back().right = nullptr;
          }

          return result;
        }
      }

      const auto& leaf = std::get<leaf_ptr>(*stack.back().p);
      CCF_ASSERT_FMT(
        leaf->index == index,
        "invalid leaf index: {} vs {}",
        ds::to_hex(leaf->index.data()),
        ds::to_hex(index.data()));

      stack.back().right = nullptr;
      stack.back().visited_left = true;

      return result;
    }

    std::vector<entry> rewind(size_t length)
    {
      std::vector<entry> up;
      for (auto it = stack.rbegin(); it != stack.rend(); it++)
      {
        if (it->right != nullptr && it->length > length)
        {
          up.push_back({it->length, hash(*it->right)});
          it->right = nullptr;
          it->visited_left = true;
        }
      }

      while (stack.size() >= 2 &&
             get_prefix(*stack[stack.size() - 2].p).size() >= length)
      {
        stack.pop_back();
      }

      if (length < depth)
      {
        depth = length;
      }

      return up;
    }

    std::vector<entry> finish()
    {
      std::vector<entry> up;
      for (auto it = stack.rbegin(); it != stack.rend(); it++)
      {
        if (it->right != nullptr)
        {
          up.push_back({it->length, hash(*it->right)});
        }
      }
      return up;
    }

  private:
    struct cursor
    {
      const position* p;
      bool visited_left = false;

      const position* right = nullptr;
      size_t length = 0;
    };

    std::vector<cursor> stack;
    size_t depth = 0;
  };

  /**
   * The prospective inserter can be used to compute what the hash of the root
   * would be if a batch of new leaves were added to a tree. The actual tree
   * is not modified.
   *
   * The algorithm is very similar to stream, but uses a `navigator` to iterate
   * over nodes of the original tree. In between every pair of insterted leaves,
   * the `navigator` tells us whether any node falls between the two indices.
   */
  template <
    typename ValueT,
    typename HashT,
    size_t SIZE,
    hash_node_t<SIZE, HashT> HASH_NODE>
  struct prefix_tree<ValueT, HashT, SIZE, HASH_NODE>::prospective_inserter
  {
    prospective_inserter(const std::optional<position>& root) : nav(root) {}

    void add(const leaf_t& l)
    {
      if (last_leaf.has_value())
      {
        CCF_ASSERT_FMT(
          *last_leaf <= l.index,
          "leaves must be inserted in order: {} > {}",
          ds::to_hex(last_leaf->data()),
          ds::to_hex(l.index.data()));

        size_t prefix = common_prefix(*last_leaf, l.index);

        // If we get a full match, then this is updating the previous value.
        // Rather than adding a new entry to the stack, we instead update the
        // latest hash.
        if (prefix == 8 * SIZE)
        {
          stack.back().hash = l.hash;
          return;
        }

        for (auto e : nav.rewind(prefix))
        {
          compress(e.length);
          stack.push_back({e.length, e.hash});
        }

        compress(prefix);
      }

      for (auto e : nav.visit(l.index))
      {
        stack.push_back({e.length, e.hash});
      }
      stack.push_back(entry{8 * SIZE, l.hash});
      last_leaf = l.index;
    }

    HashT hash()
    {
      for (auto x : nav.finish())
      {
        compress(x.length);
        stack.push_back({x.length, x.hash});
      }

      compress(0);
      if (stack.empty())
      {
        return {};
      }
      else
      {
        return stack.at(0).hash;
      }
    }

  private:
    void compress(size_t length)
    {
      while (stack.size() >= 2 && stack[stack.size() - 2].length >= length)
      {
        entry last = stack.back();
        stack.pop_back();
        auto prefix = last_leaf->first(stack.back().length);

        stack.back().hash = HASH_NODE(prefix, stack.back().hash, last.hash);
      }

      if (!stack.empty() && stack.back().length > length)
      {
        stack.back().length = length;
      }
    }

    // Index of the last leaf we hashed.
    std::optional<bitvector<SIZE>> last_leaf;

    struct entry
    {
      size_t length;
      HashT hash;
    };
    std::vector<entry> stack;

    navigator nav;
  };
}
