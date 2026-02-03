package aws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type CreditSummary struct {
	UsedAmount  float64
	Currency    string
	PeriodStart string
	PeriodEnd   string
}

type costExplorerRequest struct {
	TimePeriod  timePeriod `json:"TimePeriod"`
	Granularity string     `json:"Granularity"`
	Metrics     []string   `json:"Metrics"`
}

type timePeriod struct {
	Start string `json:"Start"`
	End   string `json:"End"`
}

type costExplorerMetric struct {
	Amount string `json:"Amount"`
	Unit   string `json:"Unit"`
}

type costExplorerResponse struct {
	ResultsByTime []struct {
		TimePeriod timePeriod                    `json:"TimePeriod"`
		Total      map[string]costExplorerMetric `json:"Total"`
	} `json:"ResultsByTime"`
}

type costExplorerError struct {
	Type    string `json:"__type"`
	Message string `json:"Message"`
}

func FetchMonthlyCreditUsage(ctx context.Context, ak, sk, proxy string) (CreditSummary, error) {
	if ak == "" || sk == "" {
		return CreditSummary{}, errors.New("missing credentials")
	}
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	payload := costExplorerRequest{
		TimePeriod: timePeriod{
			Start: start.Format("2006-01-02"),
			End:   end.Format("2006-01-02"),
		},
		Granularity: "MONTHLY",
		Metrics:     []string{"Credit"},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return CreditSummary{}, err
	}

	client, err := baseHTTPClient(proxy)
	if err != nil {
		return CreditSummary{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ce.us-east-1.amazonaws.com", bytes.NewReader(payloadBytes))
	if err != nil {
		return CreditSummary{}, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSInsightsIndexService.GetCostAndUsage")

	credProvider := credentials.NewStaticCredentialsProvider(ak, sk, "")
	creds, err := credProvider.Retrieve(ctx)
	if err != nil {
		return CreditSummary{}, err
	}

	hash := sha256.Sum256(payloadBytes)
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, creds, req, hex.EncodeToString(hash[:]), "ce", "us-east-1", time.Now().UTC()); err != nil {
		return CreditSummary{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return CreditSummary{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var ceErr costExplorerError
		if err := json.NewDecoder(resp.Body).Decode(&ceErr); err == nil && ceErr.Message != "" {
			return CreditSummary{}, fmt.Errorf("cost explorer error: %s", ceErr.Message)
		}
		return CreditSummary{}, fmt.Errorf("cost explorer request failed: %s", resp.Status)
	}

	var out costExplorerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CreditSummary{}, err
	}
	if len(out.ResultsByTime) == 0 {
		return CreditSummary{}, errors.New("empty cost explorer response")
	}
	result := out.ResultsByTime[0]
	metric, ok := result.Total["Credit"]
	if !ok {
		return CreditSummary{}, errors.New("credit metric missing")
	}
	amount, err := strconv.ParseFloat(metric.Amount, 64)
	if err != nil {
		return CreditSummary{}, err
	}
	return CreditSummary{
		UsedAmount:  amount,
		Currency:    metric.Unit,
		PeriodStart: result.TimePeriod.Start,
		PeriodEnd:   result.TimePeriod.End,
	}, nil
}
