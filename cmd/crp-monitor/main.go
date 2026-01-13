package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/deployments"
	"github.com/Abdullah1738/juno-intents/offchain/junocashcli"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
	"github.com/Abdullah1738/juno-intents/protocol"
)

const (
	crpConfigSeed     = "config"
	crpCheckpointSeed = "checkpoint"
	crpHeightSeed     = "height"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" || argv[0] == "help" {
		usage(os.Stdout)
		return nil
	}

	switch argv[0] {
	case "check":
		return cmdCheck(argv[1:])
	case "watch":
		return cmdWatch(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "crp-monitor: verifies Solana CRP finalized checkpoints against a local junocashd")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  crp-monitor check --deployment <name> [--deployments deployments.json] [--rpc-url <url>] [--junocash-cli <path>] [--junocash-arg <arg>...] [--max-lag <blocks>]")
	fmt.Fprintln(w, "  crp-monitor watch --deployment <name> [--deployments deployments.json] [--rpc-url <url>] [--junocash-cli <path>] [--junocash-arg <arg>...] [--max-lag <blocks>] [--interval 10s]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  SOLANA_RPC_URL / HELIUS_RPC_URL / (HELIUS_API_KEY + HELIUS_CLUSTER)")
}

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*m = append(*m, value)
	return nil
}

func cmdCheck(argv []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentsPath string
		deploymentName  string
		rpcURL          string

		junocashPath string
		junocashArgs multiString

		maxLag uint64
	)

	fs.StringVar(&deploymentsPath, "deployments", "deployments.json", "Path to deployments.json")
	fs.StringVar(&deploymentName, "deployment", "", "Deployment name (must exist in deployments.json)")
	fs.StringVar(&rpcURL, "rpc-url", "", "Override Solana RPC URL (default: deployment rpc_url or env)")
	fs.StringVar(&junocashPath, "junocash-cli", "junocash-cli", "Path to junocash-cli")
	fs.Var(&junocashArgs, "junocash-arg", "Extra junocash-cli arg (repeatable)")
	fs.Uint64Var(&maxLag, "max-lag", 20, "Max allowed lag (blocks) before status becomes Degraded")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentName == "" {
		return errors.New("--deployment is required")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}

	d, err := loadDeployment(deploymentsPath, deploymentName)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rpc, err := rpcClientForDeployment(d, rpcURL)
	if err != nil {
		return err
	}

	jc := junocashcli.New(junocashPath, []string(junocashArgs))

	rep, err := checkOnce(ctx, rpc, jc, d, maxLag)
	if err != nil {
		return err
	}
	return printJSON(os.Stdout, rep)
}

func cmdWatch(argv []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentsPath string
		deploymentName  string
		rpcURL          string

		junocashPath string
		junocashArgs multiString

		maxLag    uint64
		intervalS string
	)

	fs.StringVar(&deploymentsPath, "deployments", "deployments.json", "Path to deployments.json")
	fs.StringVar(&deploymentName, "deployment", "", "Deployment name (must exist in deployments.json)")
	fs.StringVar(&rpcURL, "rpc-url", "", "Override Solana RPC URL (default: deployment rpc_url or env)")
	fs.StringVar(&junocashPath, "junocash-cli", "junocash-cli", "Path to junocash-cli")
	fs.Var(&junocashArgs, "junocash-arg", "Extra junocash-cli arg (repeatable)")
	fs.Uint64Var(&maxLag, "max-lag", 20, "Max allowed lag (blocks) before status becomes Degraded")
	fs.StringVar(&intervalS, "interval", "10s", "Polling interval")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentName == "" {
		return errors.New("--deployment is required")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}

	interval, err := time.ParseDuration(intervalS)
	if err != nil || interval <= 0 {
		return fmt.Errorf("invalid --interval: %q", intervalS)
	}

	d, err := loadDeployment(deploymentsPath, deploymentName)
	if err != nil {
		return err
	}

	rpc, err := rpcClientForDeployment(d, rpcURL)
	if err != nil {
		return err
	}
	jc := junocashcli.New(junocashPath, []string(junocashArgs))

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		rep, err := checkOnce(ctx, rpc, jc, d, maxLag)
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "check error:", err)
		} else {
			_ = printJSON(os.Stdout, rep)
		}
		<-t.C
	}
}

type status string

const (
	statusHealthy  status = "Healthy"
	statusDegraded status = "Degraded"
	statusUnsafe   status = "Unsafe"
)

type report struct {
	Status    status    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Deployment struct {
		Name         string `json:"name"`
		DeploymentID string `json:"deployment_id"`
		CrpProgramID string `json:"crp_program_id"`
	} `json:"deployment"`
	Solana struct {
		RPCURL                string `json:"rpc_url,omitempty"`
		Config                string `json:"config"`
		Halted                bool   `json:"halted"`
		LatestFinalizedHeight uint64 `json:"latest_finalized_height,omitempty"`
		LatestOrchardRootHex  string `json:"latest_orchard_root_hex,omitempty"`
		LagBlocks             uint64 `json:"lag_blocks,omitempty"`
	} `json:"solana"`
	JunoCash struct {
		TipHeight             uint64 `json:"tip_height,omitempty"`
		LatestFinalizedHash   string `json:"latest_finalized_hash,omitempty"`
		LatestFinalOrchardHex string `json:"latest_final_orchard_root_hex,omitempty"`
	} `json:"junocash"`
	Alerts []string `json:"alerts,omitempty"`
}

func checkOnce(ctx context.Context, rpc *solanarpc.Client, jc *junocashcli.Client, d deployments.Deployment, maxLag uint64) (report, error) {
	var rep report
	rep.Timestamp = time.Now().UTC()
	rep.Deployment.Name = d.Name
	rep.Deployment.DeploymentID = d.DeploymentID
	rep.Deployment.CrpProgramID = d.CheckpointRegistryProgramID
	rep.Solana.RPCURL = strings.TrimSpace(d.RPCURL)

	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(d.DeploymentID), "0x"))
	if err != nil {
		return rep, fmt.Errorf("parse deployment_id: %w", err)
	}
	crpProgram, err := solana.ParsePubkey(d.CheckpointRegistryProgramID)
	if err != nil {
		return rep, fmt.Errorf("parse crp program id: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte(crpConfigSeed), deploymentID[:]}, crpProgram)
	if err != nil {
		return rep, fmt.Errorf("derive crp config pda: %w", err)
	}
	rep.Solana.Config = cfgPDA.Base58()

	cfgRaw, err := rpc.AccountDataBase64(ctx, cfgPDA.Base58())
	if err != nil {
		return rep, fmt.Errorf("fetch crp config: %w", err)
	}
	cfg, err := decodeCrpConfigV1(cfgRaw)
	if err != nil {
		return rep, fmt.Errorf("decode crp config: %w", err)
	}
	if cfg.Version != 1 || cfg.DeploymentID != [32]byte(deploymentID) {
		return rep, errors.New("unexpected crp config data")
	}
	rep.Solana.Halted = cfg.Paused

	records, err := rpc.ProgramAccountsByDataSizeBase64(ctx, crpProgram.Base58(), 43)
	if err != nil {
		return rep, fmt.Errorf("list height records: %w", err)
	}

	var heights []crpHeightV1
	for _, a := range records {
		rec, err := decodeCrpHeightV1(a.Data)
		if err != nil {
			continue
		}
		expected, _, err := solana.FindProgramAddress(
			[][]byte{[]byte(crpHeightSeed), cfgPDA[:], u64LE(rec.Height)},
			crpProgram,
		)
		if err != nil {
			continue
		}
		if expected.Base58() != a.Pubkey {
			continue
		}
		heights = append(heights, rec)
	}

	sort.Slice(heights, func(i, j int) bool { return heights[i].Height < heights[j].Height })

	var latest *crpHeightV1
	for i := len(heights) - 1; i >= 0; i-- {
		if heights[i].Finalized {
			latest = &heights[i]
			break
		}
	}

	tip, err := jc.BlockCount(ctx)
	if err != nil {
		return rep, fmt.Errorf("junocash getblockcount: %w", err)
	}
	rep.JunoCash.TipHeight = tip

	if cfg.Paused {
		rep.Alerts = append(rep.Alerts, "CRP halted on-chain (conflict or manual halt)")
	}

	if latest == nil {
		rep.Status = statusDegraded
		rep.Alerts = append(rep.Alerts, "no finalized CRP heights found")
		return rep, nil
	}

	rep.Solana.LatestFinalizedHeight = latest.Height
	rep.Solana.LatestOrchardRootHex = hex.EncodeToString(latest.OrchardRoot[:])

	if tip >= latest.Height {
		rep.Solana.LagBlocks = tip - latest.Height
	} else {
		rep.Solana.LagBlocks = 0
		rep.Alerts = append(rep.Alerts, "CRP finalized height is ahead of local junocashd tip")
	}

	bh, err := jc.BlockHash(ctx, latest.Height)
	if err != nil {
		return rep, fmt.Errorf("junocash getblockhash: %w", err)
	}
	blk, err := jc.Block(ctx, bh)
	if err != nil {
		return rep, fmt.Errorf("junocash getblock: %w", err)
	}
	rep.JunoCash.LatestFinalizedHash = strings.TrimSpace(strings.Trim(blk.Hash, "\""))
	rep.JunoCash.LatestFinalOrchardHex = strings.TrimSpace(strings.Trim(blk.FinalOrchardRoot, "\""))

	orchardRoot, err := parseHex32(blk.FinalOrchardRoot)
	if err != nil {
		return rep, fmt.Errorf("parse junocash finalorchardroot: %w", err)
	}
	if orchardRoot != latest.OrchardRoot {
		rep.Alerts = append(rep.Alerts, "orchard root mismatch vs junocashd")
	}

	checkpointPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte(crpCheckpointSeed), cfgPDA[:], latest.OrchardRoot[:]},
		crpProgram,
	)
	if err != nil {
		return rep, fmt.Errorf("derive checkpoint pda: %w", err)
	}
	cpRaw, err := rpc.AccountDataBase64(ctx, checkpointPDA.Base58())
	if err != nil {
		return rep, fmt.Errorf("fetch checkpoint: %w", err)
	}
	cp, err := decodeCrpCheckpointV1(cpRaw)
	if err != nil {
		return rep, fmt.Errorf("decode checkpoint: %w", err)
	}
	if cp.Version != 1 || cp.Height != latest.Height || cp.OrchardRoot != latest.OrchardRoot || !cp.Finalized {
		rep.Alerts = append(rep.Alerts, "unexpected checkpoint account contents")
	}

	blockHash, err := parseHex32(blk.Hash)
	if err != nil {
		return rep, fmt.Errorf("parse junocash block hash: %w", err)
	}
	if cp.BlockHash != blockHash {
		rep.Alerts = append(rep.Alerts, "block hash mismatch vs junocashd")
	}

	var prevHash [32]byte
	if latest.Height != 0 && strings.TrimSpace(blk.PreviousBlockHash) != "" {
		prevHash, err = parseHex32(blk.PreviousBlockHash)
		if err != nil {
			return rep, fmt.Errorf("parse junocash previousblockhash: %w", err)
		}
	}
	if cp.PrevHash != prevHash {
		rep.Alerts = append(rep.Alerts, "prev hash mismatch vs junocashd")
	}

	rep.Status, rep.Alerts = classify(cfg.Paused, rep.Solana.LagBlocks, maxLag, rep.Alerts)
	return rep, nil
}

func loadDeployment(path, name string) (deployments.Deployment, error) {
	reg, err := deployments.Load(path)
	if err != nil {
		return deployments.Deployment{}, err
	}
	return reg.FindByName(name)
}

func rpcClientForDeployment(d deployments.Deployment, override string) (*solanarpc.Client, error) {
	if raw := strings.TrimSpace(override); raw != "" {
		return solanarpc.New(raw, nil), nil
	}
	if raw := strings.TrimSpace(d.RPCURL); raw != "" {
		return solanarpc.New(raw, nil), nil
	}
	return solanarpc.ClientFromEnv()
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type crpConfigV1 struct {
	Version               uint8
	DeploymentID          [32]byte
	Admin                 [32]byte
	Threshold             uint8
	ConflictThreshold     uint8
	FinalizationDelaySlots uint64
	OperatorCount         uint8
	Operators             [32][32]byte
	Paused                bool
}

func decodeCrpConfigV1(b []byte) (crpConfigV1, error) {
	const wantLen = 1 + 32 + 32 + 1 + 1 + 8 + 1 + (32 * 32) + 1
	if len(b) < wantLen {
		return crpConfigV1{}, fmt.Errorf("config too short: %d < %d", len(b), wantLen)
	}

	var out crpConfigV1
	out.Version = b[0]
	copy(out.DeploymentID[:], b[1:33])
	copy(out.Admin[:], b[33:65])
	out.Threshold = b[65]
	out.ConflictThreshold = b[66]
	out.FinalizationDelaySlots = uint64(b[67]) | uint64(b[68])<<8 | uint64(b[69])<<16 | uint64(b[70])<<24 |
		uint64(b[71])<<32 | uint64(b[72])<<40 | uint64(b[73])<<48 | uint64(b[74])<<56
	out.OperatorCount = b[75]
	off := 76
	for i := 0; i < 32; i++ {
		copy(out.Operators[i][:], b[off:off+32])
		off += 32
	}
	out.Paused = b[wantLen-1] != 0
	return out, nil
}

type crpHeightV1 struct {
	Version    uint8
	Height     uint64
	OrchardRoot [32]byte
	Finalized  bool
	Conflicted bool
}

func decodeCrpHeightV1(b []byte) (crpHeightV1, error) {
	const wantLen = 1 + 8 + 32 + 1 + 1
	if len(b) < wantLen {
		return crpHeightV1{}, fmt.Errorf("height record too short: %d < %d", len(b), wantLen)
	}
	var out crpHeightV1
	out.Version = b[0]
	out.Height = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24 |
		uint64(b[5])<<32 | uint64(b[6])<<40 | uint64(b[7])<<48 | uint64(b[8])<<56
	copy(out.OrchardRoot[:], b[9:41])
	out.Finalized = b[41] != 0
	out.Conflicted = b[42] != 0
	return out, nil
}

type crpCheckpointV1 struct {
	Version       uint8
	Height        uint64
	BlockHash     [32]byte
	OrchardRoot   [32]byte
	PrevHash      [32]byte
	FirstSeenSlot uint64
	Finalized     bool
}

func decodeCrpCheckpointV1(b []byte) (crpCheckpointV1, error) {
	const wantLen = 1 + 8 + 32 + 32 + 32 + 8 + 1
	if len(b) < wantLen {
		return crpCheckpointV1{}, fmt.Errorf("checkpoint too short: %d < %d", len(b), wantLen)
	}
	var out crpCheckpointV1
	out.Version = b[0]
	out.Height = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24 |
		uint64(b[5])<<32 | uint64(b[6])<<40 | uint64(b[7])<<48 | uint64(b[8])<<56
	copy(out.BlockHash[:], b[9:41])
	copy(out.OrchardRoot[:], b[41:73])
	copy(out.PrevHash[:], b[73:105])
	out.FirstSeenSlot = uint64(b[105]) | uint64(b[106])<<8 | uint64(b[107])<<16 | uint64(b[108])<<24 |
		uint64(b[109])<<32 | uint64(b[110])<<40 | uint64(b[111])<<48 | uint64(b[112])<<56
	out.Finalized = b[113] != 0
	return out, nil
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"")
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return out, errors.New("expected 32-byte hex (64 chars)")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("invalid hex")
	}
	copy(out[:], b)
	return out, nil
}

func u64LE(v uint64) []byte {
	var out [8]byte
	out[0] = byte(v)
	out[1] = byte(v >> 8)
	out[2] = byte(v >> 16)
	out[3] = byte(v >> 24)
	out[4] = byte(v >> 32)
	out[5] = byte(v >> 40)
	out[6] = byte(v >> 48)
	out[7] = byte(v >> 56)
	return out[:]
}

func classify(halted bool, lagBlocks uint64, maxLagBlocks uint64, alerts []string) (status, []string) {
	if halted || len(alerts) > 0 {
		return statusUnsafe, alerts
	}
	if lagBlocks > maxLagBlocks {
		return statusDegraded, append(alerts, "CRP liveness lag exceeds max-lag")
	}
	return statusHealthy, alerts
}
