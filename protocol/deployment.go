package protocol

import "crypto/sha256"

const purposeDeploymentID = "deployment_id"

// DeriveDeploymentID deterministically binds a deployment to:
// - the Solana program IDs (CRP + IEP)
// - the JunoCash chain (genesis block hash)
//
// This prevents cross-deployment replay of observations and receipts when the same
// proving/verifying artifacts are reused.
func DeriveDeploymentID(crpProgramID SolanaPubkey, iepProgramID SolanaPubkey, junocashGenesisHash JunoBlockHash) DeploymentID {
	h := sha256.New()
	h.Write(prefixBytes(purposeDeploymentID))
	h.Write(crpProgramID[:])
	h.Write(iepProgramID[:])
	h.Write(junocashGenesisHash[:])
	sum := h.Sum(nil)

	var out DeploymentID
	copy(out[:], sum)
	return out
}
