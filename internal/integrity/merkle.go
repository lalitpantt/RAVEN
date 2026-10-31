package integrity

import (
	"crypto/sha256"
	"errors"
)

func MerkleLeaf(encodedEntry []byte) Hash {
	b := make([]byte, 1+len(encodedEntry))
	copy(b[1:], encodedEntry)
	return sha256.Sum256(b)
}

func MerkleNode(left, right Hash) Hash {
	var b [65]byte
	b[0] = 1
	copy(b[1:33], left[:])
	copy(b[33:], right[:])
	return sha256.Sum256(b[:])
}

func MerkleRoot(leaves []Hash) (Hash, error) {
	if len(leaves) == 0 || len(leaves) > MaxBatchEntries {
		return Hash{}, errors.New("merkle tree size must be in 1..5000")
	}
	return root(leaves), nil
}

func root(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	return MerkleNode(root(leaves[:split]), root(leaves[split:]))
}

// MerkleProof returns sibling hashes in leaf-to-root order.
func MerkleProof(leaves []Hash, index uint32) ([]Hash, error) {
	if len(leaves) == 0 || len(leaves) > MaxBatchEntries || uint64(index) >= uint64(len(leaves)) {
		return nil, errors.New("invalid Merkle proof index or tree size")
	}
	proof := make([]Hash, 0, 13)
	proofFor(leaves, int(index), &proof)
	return proof, nil
}

func proofFor(leaves []Hash, index int, proof *[]Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	if index < split {
		left := proofFor(leaves[:split], index, proof)
		right := root(leaves[split:])
		*proof = append(*proof, right)
		return MerkleNode(left, right)
	}
	right := proofFor(leaves[split:], index-split, proof)
	left := root(leaves[:split])
	*proof = append(*proof, left)
	return MerkleNode(left, right)
}

func VerifyMerkleProof(leaf Hash, index, treeSize uint32, proof []Hash, expectedRoot Hash) bool {
	if treeSize == 0 || treeSize > MaxBatchEntries || index >= treeSize || len(proof) > 13 {
		return false
	}
	proofIndex := 0
	var rebuild func(uint32, uint32) (Hash, bool)
	rebuild = func(i, n uint32) (Hash, bool) {
		if n == 1 {
			return leaf, true
		}
		split := uint32(largestPowerOfTwoLessThan(int(n)))
		var child Hash
		var ok bool
		if i < split {
			child, ok = rebuild(i, split)
			if !ok || proofIndex >= len(proof) {
				return Hash{}, false
			}
			sibling := proof[proofIndex]
			proofIndex++
			return MerkleNode(child, sibling), true
		}
		child, ok = rebuild(i-split, n-split)
		if !ok || proofIndex >= len(proof) {
			return Hash{}, false
		}
		sibling := proof[proofIndex]
		proofIndex++
		return MerkleNode(sibling, child), true
	}
	got, ok := rebuild(index, treeSize)
	return ok && proofIndex == len(proof) && got == expectedRoot
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
