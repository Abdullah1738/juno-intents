package protocol

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	purposeCRPObservation    = "crp_observation"
	purposeCRPCandidateHash  = "crp_candidate_hash"
	observationEncodingBytes = 8 + 32 + 32 + 32 // height + block_hash + orchard_root + prev_hash
)

type CheckpointObservation struct {
	Height      uint64
	BlockHash   JunoBlockHash
	OrchardRoot OrchardRoot
	PrevHash    JunoBlockHash
}

func (o CheckpointObservation) SigningBytes(deploymentID DeploymentID) []byte {
	// Canonical encoding:
	//   prefix(purposeCRPObservation) ||
	//   deployment_id (32) ||
	//   height_u64_le ||
	//   block_hash (32) ||
	//   orchard_root (32) ||
	//   prev_hash (32)
	b := make([]byte, 0, len(prefixBytes(purposeCRPObservation))+32+observationEncodingBytes)
	b = append(b, prefixBytes(purposeCRPObservation)...)
	b = append(b, deploymentID[:]...)

	var height [8]byte
	binary.LittleEndian.PutUint64(height[:], o.Height)
	b = append(b, height[:]...)

	b = append(b, o.BlockHash[:]...)
	b = append(b, o.OrchardRoot[:]...)
	b = append(b, o.PrevHash[:]...)
	return b
}

func (o CheckpointObservation) CandidateHash(deploymentID DeploymentID) CandidateHash {
	// Candidate hash is distinct from the signing bytes to avoid accidental cross-use.
	//   H(prefix(purposeCRPCandidateHash) || signing_bytes)
	h := sha256.New()
	h.Write(prefixBytes(purposeCRPCandidateHash))
	h.Write(o.SigningBytes(deploymentID))
	sum := h.Sum(nil)

	var out CandidateHash
	copy(out[:], sum)
	return out
}
