//go:build blockchain_integration

package witness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

const anvilTestKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func TestAnchorerAnvilRecoveryAndResetDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	forge := foundryBinary("forge")
	anvil := foundryBinary("anvil")
	if _, err := exec.LookPath(forge); err != nil {
		t.Skip("forge is required for tagged Anvil integration")
	}
	if _, err := exec.LookPath(anvil); err != nil {
		t.Skip("anvil is required for tagged Anvil integration")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	cmd := exec.CommandContext(ctx, anvil, "--host", "127.0.0.1", "--port", fmt.Sprint(port), "--chain-id", "31337", "--silent")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	var client *ethclient.Client
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ethclient.DialContext(ctx, url)
		if err == nil {
			if _, err = client.ChainID(ctx); err == nil {
				break
			}
			client.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Anvil did not become ready: %v", err)
	}
	defer client.Close()
	key, err := crypto.HexToECDSA(anvilTestKey)
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	deployCmd := exec.CommandContext(ctx, forge, "create", "src/LogAnchorLedger.sol:LogAnchorLedger", "--rpc-url", url, "--private-key", "0x"+anvilTestKey, "--broadcast")
	deployCmd.Dir = filepath.Join(filepath.Dir(source), "../../contracts")
	deployed, err := deployCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deploy contract: %v\n%s", err, deployed)
	}
	addressText := lineValue(string(deployed), "Deployed to: ")
	if addressText == "" {
		t.Fatalf("could not read contract address from forge output:\n%s", deployed)
	}
	address := crypto.PubkeyToAddress(key.PublicKey)
	contractAddress := common.HexToAddress(addressText)
	deploymentTx := lineValue(string(deployed), "Transaction hash: ")
	deploymentHash := common.HexToHash(deploymentTx)
	deployReceipt, err := client.TransactionReceipt(ctx, deploymentHash)
	if err != nil {
		t.Fatal(err)
	}
	stream, genesis := testIdentity()
	registerABI, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"registerStream","inputs":[{"name":"streamId","type":"bytes32"},{"name":"genesisHash","type":"bytes32"},{"name":"anchor","type":"address"}],"outputs":[],"stateMutability":"nonpayable"}]`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := registerABI.Pack("registerStream", [32]byte(stream), [32]byte(genesis), address)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendTestTransaction(ctx, client, key, contractAddress, data); err != nil {
		t.Fatal(err)
	}
	zero, err := client.HeaderByNumber(ctx, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	deployedHeader, err := client.HeaderByNumber(ctx, deployReceipt.BlockNumber)
	if err != nil {
		t.Fatal(err)
	}
	code, err := client.CodeAt(ctx, contractAddress, deployReceipt.BlockNumber)
	if err != nil {
		t.Fatal(err)
	}
	identity := ChainIdentity{ChainID: 31337, GenesisBlockHash: zero.Hash().Hex(), ContractAddress: contractAddress.Hex(), DeploymentBlock: deployReceipt.BlockNumber.Uint64(), DeploymentBlockHash: deployedHeader.Hash().Hex(), RuntimeCodeHash: crypto.Keccak256Hash(code).Hex()}
	storePath := filepath.Join(t.TempDir(), "witness.db")
	store, err := OpenStore(storePath, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	_, receiptKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-1")
	manifest, err := decodeManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Retain(ctx, manifest, ReceiptSigner{KeyID: "anvil-test", Key: receiptKey}); err != nil {
		t.Fatal(err)
	}
	var loseResponse atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		upstream, e := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		upstream.Header.Set("Content-Type", "application/json")
		response, e := http.DefaultClient.Do(upstream)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		defer response.Body.Close()
		responseBody, e := io.ReadAll(response.Body)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		if bytes.Contains(body, []byte(`"method":"eth_sendRawTransaction"`)) && loseResponse.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(responseBody)
	}))
	defer proxy.Close()
	var snapshot string
	if err := client.Client().CallContext(ctx, &snapshot, "evm_snapshot"); err != nil {
		t.Fatal(err)
	}
	anchor, err := StartAnchorer(ctx, store, stream, genesis, AnchorConfig{RPCURL: proxy.URL, Identity: identity, PrivateKeyHex: "0x" + anvilTestKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.RunOnce(ctx); err == nil {
		t.Fatal("injected lost send response was not observed")
	}
	if err := client.Client().CallContext(ctx, new(any), "anvil_mine", 1); err != nil {
		t.Fatal(err)
	}
	pending, err := store.NextAnchor(ctx)
	if err != nil || len(pending.TxBytes) == 0 || !pending.Nonce.Valid {
		t.Fatalf("signed transaction was not saved before return: %+v err=%v", pending, err)
	}
	anchor.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(storePath, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	anchor, err = StartAnchorer(ctx, store, stream, genesis, AnchorConfig{RPCURL: proxy.URL, Identity: identity, PrivateKeyHex: "0x" + anvilTestKey})
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	var retained RetainedBatch
	pending, err = store.NextAnchor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var savedTx types.Transaction
	if err := savedTx.UnmarshalBinary(pending.TxBytes); err != nil {
		t.Fatal(err)
	}
	receipt, err := client.TransactionReceipt(ctx, savedTx.Hash())
	if err != nil {
		known, _, lookupErr := client.TransactionByHash(ctx, savedTx.Hash())
		t.Fatalf("receipt unavailable for persisted tx %s (tx=%v lookup=%v): %v", savedTx.Hash(), known != nil, lookupErr, err)
	}
	badReceipt := *receipt
	badReceipt.TxHash = common.Hash{}
	if err := anchor.verifyAndConfirm(ctx, pending.BatchID, manifest, &savedTx, &badReceipt); err == nil {
		t.Fatal("mismatched receipt transaction hash was accepted")
	}
	if _, err := store.ConfirmedHead(ctx); err != nil {
		t.Fatal(err)
	}
	if err := anchor.RunOnce(ctx); err != nil {
		t.Fatalf("valid receipt was not recoverable after mismatch: %v", err)
	}
	retained, err = store.GetBatch(ctx, stream, 1)
	if retained.Acknowledgement.AnchorState != "confirmed" || !strings.Contains(string(retained.Acknowledgement.AnchorReceipt), `"status":"confirmed"`) {
		t.Fatalf("restart did not reconcile receipt: %+v", retained)
	}
	auditor := NewLedgerAuditor(store, anchor, ReceiptSigner{KeyID: "anvil-test", Key: receiptKey})
	if err := store.CreateAudit(ctx, "anvil-ledger-audit"); err != nil {
		t.Fatal(err)
	}
	var auditTarget AuditTarget
	var auditPrefix AuditPrefix
	if err := auditor.scan(ctx, "anvil-ledger-audit", &auditTarget, &auditPrefix); err != nil {
		t.Fatalf("sequential audit rejected the anchored ledger: %v", err)
	}
	if err := store.FinishAudit(ctx, "anvil-ledger-audit", "passed", auditTarget, auditPrefix, "", ""); err != nil {
		t.Fatal(err)
	}
	auditRun, err := store.GetAudit(ctx, "anvil-ledger-audit")
	if err != nil || auditRun.Result != "passed" || auditRun.VerifiedPrefix.BatchID != 1 || auditRun.Target.BlockHash == nil {
		t.Fatalf("ledger audit did not persist its fixed target and coverage: %+v err=%v", auditRun, err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER witness_batches_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE witness_batches SET manifest_json='{}' WHERE stream_id=? AND batch_id=1`, stream[:]); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAudit(ctx, "anvil-ledger-audit-tamper"); err != nil {
		t.Fatal(err)
	}
	if err := auditor.scan(ctx, "anvil-ledger-audit-tamper", &auditTarget, &auditPrefix); err == nil {
		t.Fatal("full ledger audit accepted a tampered retained manifest")
	}
	if err := anchor.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wrongChainStore, err := OpenStore(filepath.Join(t.TempDir(), "wrong-chain.db"), stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongChainStore.Close()
	wrongChain := identity
	wrongChain.ChainID = 1
	if _, err := StartAnchorer(ctx, wrongChainStore, stream, genesis, AnchorConfig{RPCURL: url, Identity: wrongChain, PrivateKeyHex: "0x" + anvilTestKey}); err == nil {
		t.Fatal("wrong chain ID was accepted")
	}
	wrongContractStore, err := OpenStore(filepath.Join(t.TempDir(), "wrong-contract.db"), stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongContractStore.Close()
	wrongContract := identity
	wrongContract.ContractAddress = "0x0000000000000000000000000000000000000002"
	wrongContractAnchor, err := StartAnchorer(ctx, wrongContractStore, stream, genesis, AnchorConfig{RPCURL: url, Identity: wrongContract, PrivateKeyHex: "0x" + anvilTestKey})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongContractAnchor.Close()
	if err := wrongContractAnchor.RunOnce(ctx); err == nil {
		t.Fatal("wrong contract address was accepted")
	}
	var reverted bool
	if err := client.Client().CallContext(ctx, &reverted, "evm_revert", snapshot); err != nil {
		t.Fatal(err)
	}
	if !reverted {
		t.Fatal("Anvil did not restore the pre-anchor snapshot")
	}
	if err := anchor.RunOnce(ctx); err == nil {
		t.Fatal("chain reset was silently accepted")
	}
	retained, err = store.GetBatch(ctx, stream, 1)
	if err != nil || retained.Acknowledgement.AnchorState != "failed" || !strings.Contains(string(retained.Acknowledgement.AnchorReceipt), `"status":"reorged"`) {
		t.Fatalf("reorg status was not recorded: %+v err=%v", retained, err)
	}
	head, err := store.ConfirmedHead(ctx)
	if err != nil || head.BatchID != 0 {
		t.Fatalf("reorged batch remained trusted: %+v err=%v", head, err)
	}
}

func sendTestTransaction(ctx context.Context, c *ethclient.Client, key *ecdsa.PrivateKey, to common.Address, data []byte) error {
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := c.PendingNonceAt(ctx, from)
	if err != nil {
		return err
	}
	price, err := c.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	gas, err := c.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, GasPrice: price, Data: data})
	if err != nil {
		return err
	}
	tx := types.NewTransaction(nonce, to, big.NewInt(0), gas, price, data)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		return err
	}
	return c.SendTransaction(ctx, signed)
}

func foundryBinary(name string) string {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".foundry", "bin", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return name
}
func lineValue(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
