package inspection

import (
	"errors"
	"math"
)

const (
	maximumReportFindings             = 10_000
	reportDocumentFixedBudget         = 8 * 1024
	reportItemFixedBudget             = 512
	reportTargetFixedBudget           = 2 * 1024
	reportFindingFixedBudget          = 2 * 1024
	reportFindingFixedEvidenceBudget  = 1536
	reportUnknownCommandIdentityBytes = 128
	maximumHTMLEscapeExpansion        = 6
)

var (
	ErrReportBudgetExceeded = errors.New("inspection report budget exceeds persisted render limits")
	ErrReportBudgetOverflow = errors.New("inspection report budget arithmetic overflow")
)

type ReportBudget struct {
	Findings             int
	MaximumRenderedBytes int
}

// estimateReportBudget conservatively accounts for the immutable report shape
// before a Run, Job, command, or outbox row is allocated. Every external byte
// is charged at the maximum HTML escaping expansion, while fixed JSON/HTML,
// threshold, timestamp, evidence, and reference fields use explicit reserves.
func estimateReportBudget(items []Item, targets []TargetRun) (ReportBudget, error) {
	if len(items) == 0 || len(items) > maxSnapshotItems || len(targets) == 0 || len(targets) > maxSnapshotTargets {
		return ReportBudget{}, ErrReportBudgetExceeded
	}
	findings := 0
	if err := checkedReportProduct(len(items), len(targets), &findings); err != nil {
		return ReportBudget{}, err
	}
	if findings > maximumReportFindings {
		return ReportBudget{}, ErrReportBudgetExceeded
	}
	total := reportDocumentFixedBudget
	for _, item := range items {
		if err := validateReportText(item.Name); err != nil {
			return ReportBudget{}, err
		}
		if err := validateReportText(item.Category); err != nil {
			return ReportBudget{}, err
		}
		if err := validateReportText(item.RecommendationTemplate); err != nil {
			return ReportBudget{}, err
		}
		if err := validateReportText(item.DocumentationURL); err != nil {
			return ReportBudget{}, err
		}
		if err := checkedReportAdd(&total, reportItemFixedBudget); err != nil {
			return ReportBudget{}, err
		}
		for _, value := range []string{item.ID, item.Name, item.Category, item.DocumentationURL} {
			if err := addEscapedReportText(&total, value); err != nil {
				return ReportBudget{}, err
			}
		}
	}
	for _, target := range targets {
		for _, value := range []string{target.TargetID, target.DisplayName, target.Host} {
			if err := validateReportText(value); err != nil {
				return ReportBudget{}, err
			}
		}
		if err := checkedReportAdd(&total, reportTargetFixedBudget); err != nil {
			return ReportBudget{}, err
		}
		for _, value := range []string{target.TargetID, target.DisplayName, target.Host} {
			if err := addEscapedReportText(&total, value); err != nil {
				return ReportBudget{}, err
			}
		}
		commandBudget := 0
		if err := checkedReportProduct(reportUnknownCommandIdentityBytes, maximumHTMLEscapeExpansion, &commandBudget); err != nil {
			return ReportBudget{}, err
		}
		if err := checkedReportAdd(&total, commandBudget); err != nil {
			return ReportBudget{}, err
		}
	}
	for _, target := range targets {
		for _, item := range items {
			if err := checkedReportAdd(&total, reportFindingFixedBudget, reportFindingFixedEvidenceBudget); err != nil {
				return ReportBudget{}, err
			}
			for _, value := range []string{target.TargetID, item.ID, item.RecommendationTemplate} {
				if err := addEscapedReportText(&total, value); err != nil {
					return ReportBudget{}, err
				}
			}
			if total > maximumReportBytes {
				return ReportBudget{}, ErrReportBudgetExceeded
			}
		}
	}
	if total > maximumReportBytes {
		return ReportBudget{}, ErrReportBudgetExceeded
	}
	return ReportBudget{Findings: findings, MaximumRenderedBytes: total}, nil
}

func checkedReportProduct(left, right int, result *int) error {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt/left) {
		return ErrReportBudgetOverflow
	}
	if result != nil {
		*result = left * right
	}
	return nil
}

func checkedReportAdd(total *int, values ...int) error {
	if total == nil || *total < 0 {
		return ErrReportBudgetOverflow
	}
	for _, value := range values {
		if value < 0 || value > math.MaxInt-*total {
			return ErrReportBudgetOverflow
		}
		*total += value
	}
	return nil
}

func addEscapedReportText(total *int, value string) error {
	expanded := 0
	if err := checkedReportProduct(len(value), maximumHTMLEscapeExpansion, &expanded); err != nil {
		return err
	}
	return checkedReportAdd(total, expanded)
}
