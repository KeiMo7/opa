// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/open-policy-agent/opa/v1/plugins/logs/ledger"
)

type ledgerParams struct {
	keyFile    string
	pubKeyFile string
	outputFile string
}

func initLedger(root *cobra.Command, _ string) {
	params := &ledgerParams{}

	verifyCmd := &cobra.Command{
		Use:          "verify <directory> [<directory> [...]]",
		Short:        "Verify tamper-evident decision ledgers",
		SilenceUsage: true,
		Long: `Verify one or more decision ledger directories.

The verifier replays every segment's digest chain and the cross-segment
chain, locates the first anomaly (truncation, deleted or reordered records,
modified content, or a replaced segment) and reports the confirmed record
prefix. When several directories are given, missing sequence ranges are
listed separately per ledger instance.

HS256 ledgers require --key (the HMAC secret); EdDSA ledgers require
--public-key (the Ed25519 public key in PEM form). SHA256 ledgers need
neither. Exit code is non-zero when verification fails.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runLedgerVerify(params, args)
		},
	}

	verifyCmd.Flags().StringVar(&params.keyFile, "key", "", "path to the HMAC key file (HS256 ledgers)")
	verifyCmd.Flags().StringVar(&params.pubKeyFile, "public-key", "", "path to the Ed25519 public key PEM file (EdDSA ledgers)")
	verifyCmd.Flags().StringVarP(&params.outputFile, "output", "o", "", "write a machine-parseable JSON report to this file")

	ledgerCmd := &cobra.Command{
		Use:   "ledger",
		Short: "Manage and verify local decision ledgers",
	}
	ledgerCmd.AddCommand(verifyCmd)
	root.AddCommand(ledgerCmd)
}

func runLedgerVerify(params *ledgerParams, dirs []string) error {
	opts := ledger.VerifyOptions{}

	if params.keyFile != "" {
		key, err := os.ReadFile(params.keyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		opts.HMACKey = key
	}
	if params.pubKeyFile != "" {
		raw, err := os.ReadFile(params.pubKeyFile)
		if err != nil {
			return fmt.Errorf("read public key file: %w", err)
		}
		pub, err := ledger.ParseEd25519PublicKeyPEM(raw)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		opts.PublicKey = pub
	}

	report, err := ledger.VerifyDirectories(dirs, opts)
	if err != nil {
		return err
	}

	fmt.Print(report.Text())

	if params.outputFile != "" {
		if err := report.WriteJSON(params.outputFile); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		fmt.Printf("machine-readable report written to %s\n", params.outputFile)
	}

	if !report.OK {
		return errors.New("ledger verification failed")
	}
	return nil
}
