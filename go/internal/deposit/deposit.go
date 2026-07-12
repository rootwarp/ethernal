// Package deposit orchestrates the per-pubkey BLS signing pipeline and
// enforces self-verification. It is the only package that knows the full
// domain story: it precomputes the deposit domain once at construction time
// and then uses it for every signing operation in Generate.
//
// The driving correctness constraint is "verify-before-write": every signature
// is re-verified immediately after signing. A single failed verification
// aborts the entire run with no partial output.
package deposit

import (
	"context"
	"errors"
	"fmt"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/ssz"
)

// ErrPubkeyMismatch is returned when the signer's public key does not match
// a requested pubkey. The error message includes the hex of the offending key.
var ErrPubkeyMismatch = errors.New("pubkey mismatch")

// ErrSelfVerifyFailed is returned when BLS self-verification fails immediately
// after signing. This indicates a bug in the signer or SSZ pipeline and should
// never occur in practice.
var ErrSelfVerifyFailed = errors.New("self-verification failed")

// Request describes a batch of deposit entries to generate. All pubkeys share
// the same withdrawal credentials, amount, and network.
type Request struct {
	// Network is the target Ethereum network.
	Network network.Network

	// Pubkeys is the list of validator public keys to generate deposits for.
	// Each must match the signer's public key.
	Pubkeys [][48]byte

	// WithdrawalCredentials is the 32-byte withdrawal credentials applied
	// uniformly to every entry in this request.
	WithdrawalCredentials [32]byte

	// AmountGwei is the deposit amount in Gwei (default: 32_000_000_000).
	AmountGwei uint64

	// DepositCLIVersion is the version string written into the output JSON,
	// e.g. "2.7.0". It mirrors the staking-deposit-cli release that was used
	// to derive the golden test fixtures.
	DepositCLIVersion string
}

// Entry holds the fully computed and verified deposit data for a single
// validator pubkey. It contains all fields required to produce a
// Launchpad-compatible deposit_data JSON entry.
type Entry struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
	Signature             [96]byte
	DepositMessageRoot    [32]byte
	DepositDataRoot       [32]byte
	ForkVersion           [4]byte
	NetworkName           network.Network
	DepositCLIVersion     string
}

// Generator precomputes the deposit signing domain at construction time and
// uses it for every Generate call. Construct via NewGenerator.
type Generator struct {
	signer   bls.Signer
	verifier bls.Verifier
	domain   [32]byte       // precomputed: ComputeDomain(DomainDeposit, forkVersion, ZeroGVR)
	params   network.Params // stored for ForkVersion and NetworkName in entries
}

// NewGenerator constructs a Generator that signs with s, verifies with v, and
// uses the network parameters in params. The deposit domain is computed once
// here using network.DomainDeposit and network.ZeroGenesisValidatorsRoot.
func NewGenerator(s bls.Signer, v bls.Verifier, params network.Params) *Generator {
	domain := ssz.ComputeDomain(
		network.DomainDeposit,
		params.GenesisForkVersion,
		network.ZeroGenesisValidatorsRoot,
	)
	return &Generator{
		signer:   s,
		verifier: v,
		domain:   domain,
		params:   params,
	}
}

// Generate runs the per-pubkey signing pipeline for every pubkey in req.
// It returns all entries only if every entry passed self-verification.
// On any error — pubkey mismatch, sign error, verify failure, or context
// cancellation — it returns (nil, err) with no partial output.
func (g *Generator) Generate(ctx context.Context, req Request) ([]Entry, error) {
	// Guard against silent misconfiguration: the request's stated network must
	// match the network this Generator was constructed for.
	if req.Network != g.params.Name {
		return nil, fmt.Errorf("network mismatch: request %q but generator is configured for %q",
			req.Network, g.params.Name)
	}

	entries := make([]Entry, 0, len(req.Pubkeys))

	for i, pk := range req.Pubkeys {
		// Step 0: honour context cancellation before each unit of work.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Step 1: assert that the signer's pubkey matches the requested pubkey.
		signerPub, err := g.signer.PublicKey()
		if err != nil {
			return nil, err
		}
		if signerPub != pk {
			return nil, fmt.Errorf("%w: pubkey[%d]=0x%x", ErrPubkeyMismatch, i, pk[:])
		}

		// Step 2-3: build the deposit message and compute its hash tree root.
		msg := ssz.DepositMessage{
			Pubkey:                pk,
			WithdrawalCredentials: req.WithdrawalCredentials,
			Amount:                req.AmountGwei,
		}
		msgRoot := msg.HashTreeRoot()

		// Step 4: compute the signing root using the precomputed domain.
		signingRoot := ssz.ComputeSigningRoot(msgRoot, g.domain)

		// Step 5: sign.
		sig, err := g.signer.Sign(signingRoot)
		if err != nil {
			return nil, err
		}

		// Step 6: self-verify.
		ok, err := g.verifier.Verify(pk, signingRoot, sig)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: pubkey[%d]=0x%x", ErrSelfVerifyFailed, i, pk[:])
		}

		// Step 7-8: build deposit data and compute its hash tree root.
		data := ssz.DepositData{
			Pubkey:                pk,
			WithdrawalCredentials: req.WithdrawalCredentials,
			Amount:                req.AmountGwei,
			Signature:             sig,
		}
		dataRoot := data.HashTreeRoot()

		// Step 9: emit the completed entry.
		entries = append(entries, Entry{
			Pubkey:                pk,
			WithdrawalCredentials: req.WithdrawalCredentials,
			Amount:                req.AmountGwei,
			Signature:             sig,
			DepositMessageRoot:    msgRoot,
			DepositDataRoot:       dataRoot,
			ForkVersion:           g.params.GenesisForkVersion,
			NetworkName:           g.params.Name,
			DepositCLIVersion:     req.DepositCLIVersion,
		})
	}

	return entries, nil
}
