package openid4vp_test

import (
	"context"
	"testing"
	"vc/pkg/configuration"
	"vc/pkg/openid4vp"
)

func TestPresentationBuilder_BuildFromScopes(t *testing.T) {
	ctx := context.Background()

	// Load test templates
	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Note: gopls may show a false positive error here due to interface analysis limitations
	// The code compiles and runs correctly - the interface is properly satisfied at runtime
	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name        string
		scopes      []string
		expectError bool
		expectedID  string
	}{
		{
			name:        "PID scope",
			scopes:      []string{"openid", "pid"},
			expectError: false,
			expectedID:  "basic_pid",
		},
		{
			name:        "EHIC scope",
			scopes:      []string{"openid", "ehic"},
			expectError: false,
			expectedID:  "basic_ehic",
		},
		{
			name:        "No scopes",
			scopes:      []string{},
			expectError: true,
		},
		{
			name:        "Unknown scope",
			scopes:      []string{"unknown_scope"},
			expectError: true,
		},
		{
			name:        "Only standard OIDC scopes matched via pid",
			scopes:      []string{"openid", "profile", "pid"},
			expectError: false,
			expectedID:  "basic_pid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcql, template, err := builder.BuildFromScopes(ctx, tt.scopes)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if dcql == nil {
				t.Error("Expected DCQL query but got nil")
				return
			}

			if template == nil {
				t.Error("Expected template but got nil")
				return
			}

			if template.GetID() != tt.expectedID {
				t.Errorf("Expected template ID %s, got %s", tt.expectedID, template.GetID())
			}
		})
	}
}

func TestPresentationBuilder_BuildFromTemplate(t *testing.T) {
	ctx := context.Background()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name        string
		templateID  string
		expectError bool
	}{
		{
			name:        "Valid PID template",
			templateID:  "basic_pid",
			expectError: false,
		},
		{
			name:        "Valid EHIC template",
			templateID:  "basic_ehic",
			expectError: false,
		},
		{
			name:        "Non-existent template",
			templateID:  "does_not_exist",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcql, template, err := builder.BuildFromTemplate(ctx, tt.templateID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if dcql == nil {
				t.Error("Expected DCQL query but got nil")
				return
			}

			if template == nil {
				t.Error("Expected template but got nil")
				return
			}

			if template.GetID() != tt.templateID {
				t.Errorf("Expected template ID %s, got %s", tt.templateID, template.GetID())
			}
		})
	}
}

func TestPresentationBuilder_BuildPresentationDefinition(t *testing.T) {
	ctx := context.Background()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name                string
		scopes              []string
		expectError         bool
		minInputDescriptors int
	}{
		{
			name:                "PID scope creates descriptor",
			scopes:              []string{"openid", "pid"},
			expectError:         false,
			minInputDescriptors: 1,
		},
		{
			name:                "EHIC scope creates descriptor",
			scopes:              []string{"openid", "ehic"},
			expectError:         false,
			minInputDescriptors: 1,
		},
		{
			name:                "Only standard scopes creates generic descriptor",
			scopes:              []string{"openid", "profile"},
			expectError:         false,
			minInputDescriptors: 1,
		},
		{
			name:        "No scopes returns error",
			scopes:      []string{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd, err := builder.BuildPresentationDefinition(ctx, tt.scopes)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if pd == nil {
				t.Error("Expected PresentationDefinition but got nil")
				return
			}

			if len(pd.InputDescriptors) < tt.minInputDescriptors {
				t.Errorf("Expected at least %d input descriptors, got %d",
					tt.minInputDescriptors, len(pd.InputDescriptors))
			}

			if pd.ID == "" {
				t.Error("PresentationDefinition should have an ID")
			}
		})
	}
}

func TestPresentationBuilder_ListTemplates(t *testing.T) {
	ctx := context.Background()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	templates := builder.ListTemplates()
	if len(templates) == 0 {
		t.Error("Expected templates but got none")
	}

	// Should have at least PID and EHIC templates
	if len(templates) < 2 {
		t.Errorf("Expected at least 2 templates, got %d", len(templates))
	}
}

func TestPresentationBuilder_GetTemplate(t *testing.T) {
	ctx := context.Background()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	template, err := builder.GetTemplate("basic_pid")
	if err != nil {
		t.Errorf("Failed to get template: %v", err)
	}

	if template == nil {
		t.Error("Expected template but got nil")
	}

	if template != nil && template.GetID() != "basic_pid" {
		t.Errorf("Expected template ID 'basic_pid', got %s", template.GetID())
	}

	// Test non-existent template
	_, err = builder.GetTemplate("does_not_exist")
	if err == nil {
		t.Error("Expected error for non-existent template")
	}
}

func TestPresentationBuilder_DCQLConversion(t *testing.T) {
	ctx := context.Background()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/eudi_pid_basic.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	// Build presentation definition from PID scope
	pd, err := builder.BuildPresentationDefinition(ctx, []string{"pid"})
	if err != nil {
		t.Fatalf("Failed to build presentation definition: %v", err)
	}

	if len(pd.InputDescriptors) == 0 {
		t.Fatal("Expected at least one input descriptor")
	}

	descriptor := pd.InputDescriptors[0]

	// Verify VCT constraint is present
	hasVCTConstraint := false
	for _, field := range descriptor.Constraints.Fields {
		if len(field.Path) > 0 && field.Path[0] == "$.vct" {
			hasVCTConstraint = true
			if field.Filter != nil && field.Filter.Const != "" {
				t.Logf("VCT constraint found: %s", field.Filter.Const)
			}
		}
	}

	if !hasVCTConstraint {
		t.Error("Expected VCT constraint in input descriptor")
	}

	// Verify limit_disclosure is set
	if descriptor.Constraints.LimitDisclosure != "required" {
		t.Errorf("Expected limit_disclosure to be 'required', got %s",
			descriptor.Constraints.LimitDisclosure)
	}
}
