package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"raven/internal/integrity"
)

func testIdentity() (integrity.Hash, integrity.Hash) {
	var stream, genesis integrity.Hash
	stream[0], genesis[0] = 0x31, 0x42
	return stream, genesis
}

func makeTestManifest(t *testing.T, stream, parent integrity.Hash, batchID, firstSeq uint64, subjects ...string) []byte {
	t.Helper()
	entries := make([]BatchEntry, 0, len(subjects))
	leaves := make([]integrity.Hash, 0, len(subjects))
	for i, subjectValue := range subjects {
		seq := firstSeq + uint64(i)
		subject, rawID := subjectValue, subjectValue
		content := integrity.HashContent([]byte("content:" + subjectValue))
		metadata := integrity.HashContent([]byte("metadata:" + subjectValue))
		encoded, err := integrity.EncodeEvidenceEntry(integrity.EvidenceEntry{
			Version: integrity.CodecVersion, StreamID: stream, Sequence: seq, Kind: integrity.RawCommitted,
			SubjectID: &subject, RawID: &rawID, OccurredAtUnixNS: int64(seq), ContentDigest: content, MetadataDigest: metadata,
		})
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, integrity.MerkleLeaf(encoded))
		entries = append(entries, BatchEntry{
			EntrySeq: seq, Kind: "raw_committed", SubjectID: subject, RawID: &rawID,
			ChildOrdinal: nil, OperationID: nil, PreviousSubjectSeq: nil, OccurredAtUnixNS: int64(seq),
			ContentDigest: formatHash(content), MetadataDigest: formatHash(metadata),
		})
	}
	root, err := integrity.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	manifest := BatchManifest{Descriptor: BatchDescriptor{
		CodecVersion: 1, StreamID: formatHash(stream), BatchID: batchID, FirstSeq: firstSeq,
		LastSeq: firstSeq + uint64(len(entries)) - 1, LeafCount: uint32(len(entries)),
		MerkleRoot: formatHash(root), PreviousBatchHash: formatHash(parent),
	}, Entries: entries}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func setupWitness(t *testing.T) (*Store, *Server, integrity.Hash, integrity.Hash, ed25519.PrivateKey) {
	t.Helper()
	stream, genesis := testIdentity()
	store, err := OpenStore(filepath.Join(t.TempDir(), "witness.db"), stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, stream, strings.Repeat("p", 32), strings.Repeat("a", 32), ReceiptSigner{KeyID: "test-key-v1", Key: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	return store, server, stream, genesis, privateKey
}

func request(t *testing.T, handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func TestWitnessRetainsSignsAndServesDurableManifest(t *testing.T) {
	store, server, stream, genesis, privateKey := setupWitness(t)
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-1", "raw-2")
	path := "/v1/streams/" + formatHash(stream) + "/batches"
	res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), body)
	if res.Code != http.StatusAccepted {
		t.Fatalf("retain status=%d body=%s", res.Code, res.Body.String())
	}
	var ack Acknowledgement
	if err := json.Unmarshal(res.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	signed := integrity.SignedAcknowledgement{Acknowledgement: integrity.WitnessAcknowledgement{
		StreamID: stream, BatchID: ack.BatchID, BatchHash: mustHash(t, ack.BatchHash),
		PreviousAckHash: mustHash(t, ack.PreviousAckHash), WitnessKeyID: ack.KeyID,
		ReceivedAtNS: mustTime(t, ack.ReceivedAt).UnixNano(),
	}, Signature: mustBase64(t, ack.Signature)}
	if err := integrity.VerifyAcknowledgement(signed, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("acknowledgement signature failed: %v", err)
	}
	firstAckHash, err := integrity.AcknowledgementHash(signed)
	if err != nil {
		t.Fatal(err)
	}
	secondBody := makeTestManifest(t, stream, mustHash(t, ack.BatchHash), 2, 3, "raw-3")
	second := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), secondBody)
	if second.Code != http.StatusAccepted {
		t.Fatalf("second contiguous batch status=%d body=%s", second.Code, second.Body.String())
	}
	var secondAck Acknowledgement
	if err := json.Unmarshal(second.Body.Bytes(), &secondAck); err != nil || secondAck.PreviousAckHash != formatHash(firstAckHash) {
		t.Fatalf("acknowledgement chain is not contiguous: ack=%+v err=%v", secondAck, err)
	}
	var batches, queued int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM witness_batches`).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM witness_anchor_queue WHERE state='pending'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if batches != 2 || queued != 2 {
		t.Fatalf("acknowledged before batch+queue commit: batches=%d queue=%d", batches, queued)
	}
	duplicate := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), body)
	if duplicate.Code != http.StatusAccepted {
		t.Fatalf("identical retry status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	getPath := path + "/1"
	get := request(t, server.Handler(), http.MethodGet, getPath, strings.Repeat("a", 32), nil)
	if get.Code != http.StatusOK {
		t.Fatalf("get retained batch status=%d body=%s", get.Code, get.Body.String())
	}
	var retained RetainedBatch
	if err := json.Unmarshal(get.Body.Bytes(), &retained); err != nil || len(retained.Manifest) == 0 || retained.Acknowledgement.BatchHash != ack.BatchHash {
		t.Fatalf("retained response is incomplete: %+v err=%v", retained, err)
	}
	statusPath := "/v1/streams/" + formatHash(stream) + "/status"
	status := request(t, server.Handler(), http.MethodGet, statusPath, strings.Repeat("a", 32), nil)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"backlog_count":2`) {
		t.Fatalf("unexpected witness status: %d %s", status.Code, status.Body.String())
	}
}

func TestWitnessEnforcesAuthValidationContinuityAndEquivocation(t *testing.T) {
	store, server, stream, genesis, _ := setupWitness(t)
	path := "/v1/streams/" + formatHash(stream) + "/batches"
	valid := makeTestManifest(t, stream, genesis, 1, 1, "raw-1")
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("a", 32), valid); res.Code != http.StatusUnauthorized {
		t.Fatalf("admin token accepted as producer: %d", res.Code)
	}
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), []byte(`{"unexpected":true}`)); res.Code != http.StatusBadRequest {
		t.Fatalf("malformed manifest status=%d body=%s", res.Code, res.Body.String())
	}
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), append(append([]byte{}, valid...), []byte(` {}`)...)); res.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON accepted: %d", res.Code)
	}
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), bytes.Repeat([]byte(" "), maxManifestBytes+1)); res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status=%d", res.Code)
	}
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), valid); res.Code != http.StatusAccepted {
		t.Fatalf("valid manifest status=%d body=%s", res.Code, res.Body.String())
	}
	conflict := makeTestManifest(t, stream, genesis, 1, 1, "different-raw")
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), conflict); res.Code != http.StatusConflict {
		t.Fatalf("equivocation status=%d body=%s", res.Code, res.Body.String())
	}
	var findings int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM witness_findings WHERE classification='equivocation'`).Scan(&findings); err != nil || findings != 1 {
		t.Fatalf("equivocation not durably recorded: count=%d err=%v", findings, err)
	}
	skipped := makeTestManifest(t, stream, mustHash(t, "0x"+strings.Repeat("0", 64)), 3, 2, "raw-2")
	if res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), skipped); res.Code != http.StatusConflict {
		t.Fatalf("skipped batch status=%d", res.Code)
	}
}

func TestWitnessRetentionFailureDoesNotAcknowledge(t *testing.T) {
	store, server, stream, genesis, _ := setupWitness(t)
	if _, err := store.db.Exec(`CREATE TRIGGER fail_queue BEFORE INSERT ON witness_anchor_queue BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	path := "/v1/streams/" + formatHash(stream) + "/batches"
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-1")
	res := request(t, server.Handler(), http.MethodPost, path, strings.Repeat("p", 32), body)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("storage failure status=%d body=%s", res.Code, res.Body.String())
	}
	var batches, queued, lastBatch int
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM witness_batches`).Scan(&batches)
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM witness_anchor_queue`).Scan(&queued)
	_ = store.db.QueryRow(`SELECT last_batch_id FROM witness_streams`).Scan(&lastBatch)
	if batches != 0 || queued != 0 || lastBatch != 0 {
		t.Fatalf("failed retention left partial state: batches=%d queue=%d head=%d", batches, queued, lastBatch)
	}
}

func TestWitnessAuditRouteIsAdminOnlyAndPersistsUnavailableResult(t *testing.T) {
	_, server, stream, _, _ := setupWitness(t)
	body, err := json.Marshal(map[string]string{"stream_id": formatHash(stream), "type": "ledger"})
	if err != nil {
		t.Fatal(err)
	}
	if res := request(t, server.Handler(), http.MethodPost, "/v1/audits", strings.Repeat("p", 32), body); res.Code != http.StatusUnauthorized {
		t.Fatalf("producer credential scheduled an audit: %d", res.Code)
	}
	if res := request(t, server.Handler(), http.MethodPost, "/v1/audits", strings.Repeat("a", 32), []byte(`{"stream_id":"bad","type":"ledger"}`)); res.Code != http.StatusBadRequest {
		t.Fatalf("malformed audit request status=%d body=%s", res.Code, res.Body.String())
	}
	res := request(t, server.Handler(), http.MethodPost, "/v1/audits", strings.Repeat("a", 32), body)
	if res.Code != http.StatusAccepted {
		t.Fatalf("admin audit request was not accepted: %d %s", res.Code, res.Body.String())
	}
	var accepted struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &accepted); err != nil || accepted.RunID == "" {
		t.Fatalf("audit run ID missing: %s err=%v", res.Body.String(), err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := request(t, server.Handler(), http.MethodGet, "/v1/audits/"+accepted.RunID, strings.Repeat("a", 32), nil)
		var run AuditRun
		if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &run) != nil {
			t.Fatalf("audit status unavailable: %d %s", got.Code, got.Body.String())
		}
		if run.State == "completed" {
			if run.Result != "unavailable" || run.FailureClass == nil || *run.FailureClass != "chain_unavailable" {
				t.Fatalf("audit without a chain incorrectly passed: %+v", run)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("audit did not finish within deadline")
}

func TestWitnessReopenPinsIdentityAndRejectsFutureSchema(t *testing.T) {
	stream, genesis := testIdentity()
	path := filepath.Join(t.TempDir(), "witness.db")
	store, err := OpenStore(path, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, stream, integrity.HashContent([]byte("replacement genesis"))); err == nil {
		t.Fatal("witness allowed configured genesis replacement")
	}
	store, err = OpenStore(path, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`PRAGMA user_version=4`); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := OpenStore(path, stream, genesis); err == nil {
		t.Fatal("witness accepted a future schema")
	}
}

func TestWitnessKeyGenerationIsPrivateAndNoClobber(t *testing.T) {
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "receipt-key.b64"), filepath.Join(dir, "receipt-key.pub")
	if err := GenerateReceiptKey(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%v err=%v", info.Mode().Perm(), err)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateBytes)))
	publicKey, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicBytes)))
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("generated key sizes are invalid")
	}
	if err := GenerateReceiptKey(privatePath, publicPath); err == nil {
		t.Fatal("keygen overwrote existing identity")
	}
}

func TestDecodeManifestRecomputesMerkleAndDescriptor(t *testing.T) {
	stream, genesis := testIdentity()
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-1")
	validated, err := decodeManifest(body)
	if err != nil || validated.BatchHash == (integrity.Hash{}) {
		t.Fatalf("valid manifest rejected: hash=%x err=%v", validated.BatchHash, err)
	}
	var changed map[string]any
	if err := json.Unmarshal(body, &changed); err != nil {
		t.Fatal(err)
	}
	entries := changed["entries"].([]any)
	entries[0].(map[string]any)["content_digest"] = formatHash(integrity.HashContent([]byte("tampered")))
	altered, _ := json.Marshal(changed)
	if _, err := decodeManifest(altered); err == nil {
		t.Fatal("manifest with altered entry digest retained stale root")
	}
	if _, err := decodeManifest(append(body, []byte("not-json")...)); err == nil {
		t.Fatal("manifest trailing bytes accepted")
	}
}

func TestWitnessConfigRequiresSecretReferencesAndPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "private.b64"), filepath.Join(dir, "public.b64")
	if err := GenerateReceiptKey(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	stream, genesis := testIdentity()
	configPath := filepath.Join(dir, "witness.yaml")
	contents := "listen_address: 127.0.0.1:9091\ndatabase_path: " + filepath.Join(dir, "witness.db") + "\nstream_id: " + formatHash(stream) + "\ngenesis_hash: " + formatHash(genesis) + "\nkey_id: local-key\nprivate_key_path: " + privatePath + "\nproducer_token_env: TEST_WITNESS_PRODUCER\nadmin_token_env: TEST_WITNESS_ADMIN\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_WITNESS_PRODUCER", strings.Repeat("p", 32))
	t.Setenv("TEST_WITNESS_ADMIN", strings.Repeat("a", 32))
	cfg, err := LoadConfig(configPath)
	if err != nil || cfg.StreamID != stream || cfg.GenesisHash != genesis {
		t.Fatalf("valid config failed: %+v err=%v", cfg, err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("world-readable signing key was accepted")
	}
}

func TestWitnessStoreContextCancellation(t *testing.T) {
	stream, genesis := testIdentity()
	store, err := OpenStore(":memory:", stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Status(ctx, stream); err == nil {
		t.Fatal("canceled witness status query succeeded")
	}
}

func TestAnchorTransactionAndChainIdentityAreDurableAndPinned(t *testing.T) {
	stream, genesis := testIdentity()
	path := filepath.Join(t.TempDir(), "witness.db")
	store, err := OpenStore(path, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-1")
	manifest, err := decodeManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Retain(context.Background(), manifest, ReceiptSigner{})
	if err == nil {
		t.Fatal("retention accepted an invalid signer")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Retain(context.Background(), manifest, ReceiptSigner{KeyID: "test", Key: privateKey}); err != nil {
		t.Fatal(err)
	}
	identity := ChainIdentity{ChainID: 31337, GenesisBlockHash: formatHash(genesis), ContractAddress: "0x0000000000000000000000000000000000000001", DeploymentBlock: 1, DeploymentBlockHash: formatHash(integrity.HashContent([]byte("deployment"))), RuntimeCodeHash: formatHash(integrity.HashContent([]byte("runtime")))}
	if err := store.PinChainIdentity(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if err := store.PinChainIdentity(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	changed := identity
	changed.ContractAddress = "0x0000000000000000000000000000000000000002"
	if err := store.PinChainIdentity(context.Background(), changed); err == nil {
		t.Fatal("chain identity was silently replaced")
	}
	if err := store.PersistAnchorTx(context.Background(), 1, 7, []byte("signed transaction"), []byte("transaction hash")); err != nil {
		t.Fatal(err)
	}
	pending, err := store.NextAnchor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != "running" || !pending.Nonce.Valid || pending.Nonce.Int64 != 7 || string(pending.TxBytes) != "signed transaction" || string(pending.TxHash) != "transaction hash" {
		t.Fatalf("persisted transaction is incomplete: %+v", pending)
	}
	checkpoint := integrity.HashContent([]byte("checkpoint"))
	if err := store.ConfirmAnchor(context.Background(), 1, []byte(`{"status":"confirmed"}`), 9, checkpoint[:]); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmAnchor(context.Background(), 1, []byte(`{"status":"confirmed"}`), 9, genesis[:]); err == nil {
		t.Fatal("checkpoint hash was overwritten")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pinned, err := reopened.ChainIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pinned == nil || pinned.ContractAddress != identity.ContractAddress {
		t.Fatalf("pinned identity did not survive reopen: %+v", pinned)
	}
	head, err := reopened.ConfirmedHead(context.Background())
	if err != nil || head.BatchID != 1 {
		t.Fatalf("confirmed head was not durable: %+v err=%v", head, err)
	}
	api, err := NewServer(reopened, stream, strings.Repeat("p", 32), strings.Repeat("a", 32), ReceiptSigner{KeyID: "test", Key: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, api.Handler(), http.MethodGet, "/v1/streams/"+formatHash(stream)+"/status", strings.Repeat("a", 32), nil)
	var apiStatus APIStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &apiStatus) != nil || apiStatus.ChainIdentity == nil || apiStatus.ConfirmedHead.BatchID != 1 {
		t.Fatalf("witness API omitted pinned identity or confirmed head: %d %s", response.Code, response.Body.String())
	}
}

func TestAnchorRPCOutageDoesNotBlockWitnessRetention(t *testing.T) {
	stream, genesis := testIdentity()
	store, server, _, _, _ := setupWitness(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	identity := ChainIdentity{ChainID: 31337, GenesisBlockHash: formatHash(genesis), ContractAddress: "0x0000000000000000000000000000000000000001", DeploymentBlockHash: formatHash(genesis), RuntimeCodeHash: formatHash(genesis)}
	anchor, err := StartAnchorer(context.Background(), store, stream, genesis, AnchorConfig{RPCURL: "http://127.0.0.1:1", Identity: identity, PrivateKeyHex: hex.EncodeToString(crypto.FromECDSA(key))})
	if err != nil {
		t.Fatalf("witness anchoring setup blocked API startup on unavailable RPC: %v", err)
	}
	defer anchor.Close()
	if err := anchor.RunOnce(context.Background()); err == nil {
		t.Fatal("unavailable RPC was treated as successful anchoring")
	}
	body := makeTestManifest(t, stream, genesis, 1, 1, "raw-outage")
	res := request(t, server.Handler(), http.MethodPost, "/v1/streams/"+formatHash(stream)+"/batches", strings.Repeat("p", 32), body)
	if res.Code != http.StatusAccepted {
		t.Fatalf("witness did not retain durably during RPC outage: %d %s", res.Code, res.Body.String())
	}
	var pending int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM witness_anchor_queue WHERE state='pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("offline manifest did not remain queued: count=%d err=%v", pending, err)
	}
}

func TestWitnessSchemaV1UpgradesWithoutDroppingQueuedBatches(t *testing.T) {
	stream, genesis := testIdentity()
	path := filepath.Join(t.TempDir(), "witness-v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE witness_streams(stream_id BLOB PRIMARY KEY,genesis_hash BLOB NOT NULL,last_batch_id INTEGER NOT NULL DEFAULT 0,last_seq INTEGER NOT NULL DEFAULT 0,last_batch_hash BLOB NOT NULL,last_ack_hash BLOB NOT NULL,created_at TEXT NOT NULL);
	CREATE TABLE witness_batches(stream_id BLOB,batch_id INTEGER,first_seq INTEGER,last_seq INTEGER,leaf_count INTEGER,batch_hash BLOB,manifest_hash BLOB,manifest_json BLOB,ack_hash BLOB,ack_json BLOB,received_at TEXT,PRIMARY KEY(stream_id,batch_id));
	CREATE TABLE witness_anchor_queue(stream_id BLOB,batch_id INTEGER,state TEXT NOT NULL DEFAULT 'pending',attempt_count INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,PRIMARY KEY(stream_id,batch_id));
	CREATE TABLE witness_findings(finding_id INTEGER PRIMARY KEY,stream_id BLOB,batch_id INTEGER,classification TEXT,details TEXT,detected_at TEXT);
	INSERT INTO witness_streams(stream_id,genesis_hash,last_batch_id,last_seq,last_batch_hash,last_ack_hash,created_at) VALUES(x'3100000000000000000000000000000000000000000000000000000000000000',x'4200000000000000000000000000000000000000000000000000000000000000',1,1,x'0100000000000000000000000000000000000000000000000000000000000000',zeroblob(32),'2026-10-31T00:00:00Z');
	INSERT INTO witness_batches(stream_id,batch_id,first_seq,last_seq,leaf_count,batch_hash,manifest_hash,manifest_json,ack_hash,ack_json,received_at) VALUES(x'3100000000000000000000000000000000000000000000000000000000000000',1,1,1,1,zeroblob(32),zeroblob(32),x'7b7d',zeroblob(32),x'7b7d','2026-10-31T00:00:00Z');
	INSERT INTO witness_anchor_queue(stream_id,batch_id,state,attempt_count,created_at) VALUES(x'3100000000000000000000000000000000000000000000000000000000000000',1,'pending',0,'2026-10-31T00:00:00Z');
	PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path, stream, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("v1 witness DB did not migrate to v2: version=%d err=%v", version, err)
	}
	var columns int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('witness_anchor_queue') WHERE name IN ('nonce','tx_bytes','tx_hash','receipt_json')`).Scan(&columns); err != nil || columns != 4 {
		t.Fatalf("anchoring journal columns missing after migration: count=%d err=%v", columns, err)
	}
	var state string
	if err := store.db.QueryRow(`SELECT state FROM witness_anchor_queue WHERE stream_id=? AND batch_id=1`, stream[:]).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("v1 queued batch was not preserved: state=%s err=%v", state, err)
	}
}

func mustHash(t *testing.T, value string) integrity.Hash {
	t.Helper()
	h, err := parseHash(value)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustBase64(t *testing.T, value string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
