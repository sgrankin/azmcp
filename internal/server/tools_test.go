package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTypedToolCatalogContainsOnlyImplementedOperations(t *testing.T) {
	want := map[string]bool{
		"azure_accounts": true, "azure_context_open": true, "azure_context_close": true,
		"azure_request": true, "azure_graph": true, "azure_metrics_single": true,
		"azure_metrics_batch": true, "azure_logs_query": true, "azure_export": true,
		"azure_schema_search": true, "azure_schema_get": true,
	}
	for _, tool := range catalog {
		if !want[tool.Name] {
			t.Fatal("unexpected tool", tool.Name)
		}
		delete(want, tool.Name)
		for _, removed := range []string{"JavaScript", "QuickJS", "worker", "promise", "az.request", "az.graph", "az.metrics", "az.logs", "az.ref"} {
			if strings.Contains(string(catalogJSON), removed) {
				t.Fatal("catalog advertises removed surface", removed)
			}
		}
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatal("tool input is not closed", tool.Name)
		}
	}
	if len(want) != 0 {
		t.Fatal("missing implemented tools", want)
	}
}

func typedToolArguments() map[string]map[string]any {
	resource := "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"
	return map[string]map[string]any{
		"azure_request":        {"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": "2020-01-01"},
		"azure_graph":          {"cloud": "AzureCloud", "query": "Resources | project name"},
		"azure_metrics_single": {"cloud": "AzureCloud", "resourceId": resource, "metricNames": []string{"Requests"}, "autoAdjustTimegrain": true, "validateDimensions": false},
		"azure_metrics_batch":  {"cloud": "AzureCloud", "region": "eastus", "resourceIds": []string{resource}, "metricNames": []string{"Requests"}, "metricNamespace": "Microsoft.Storage/storageAccounts"},
		"azure_logs_query":     {"cloud": "AzureCloud", "workspaceId": "33333333-3333-3333-3333-333333333333", "query": "AppRequests | count", "timespan": "PT1H"},
	}
}

func schemaArguments(t *testing.T, name string, value any, valid bool) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseArguments(name, raw)
	if (err == nil) != valid {
		t.Fatalf("%s argument admission=%v, wanted %v: %s (%v)", name, err == nil, valid, raw, err)
	}
}

func TestTypedToolInputsRequireContextAndRetainClosedHelperFields(t *testing.T) {
	for name, fields := range typedToolArguments() {
		schemaArguments(t, name, fields, false)
		fields["contextId"] = strings.Repeat("A", 43)
		schemaArguments(t, name, fields, true)
		fields["unexpected"] = true
		schemaArguments(t, name, fields, false)
		delete(fields, "unexpected")
		fields["cloud"] = "AzureChinaCloud"
		schemaArguments(t, name, fields, false)
	}
	metrics := typedToolArguments()["azure_metrics_single"]
	metrics["contextId"] = strings.Repeat("A", 43)
	metrics["autoAdjustTimegrain"] = "true"
	schemaArguments(t, "azure_metrics_single", metrics, false)
	metrics["autoAdjustTimegrain"] = true
	metrics["metricNames"] = []string{"Requests,Errors"}
	schemaArguments(t, "azure_metrics_single", metrics, false)
	metrics["metricNames"] = []string{"Requests\n"}
	schemaArguments(t, "azure_metrics_single", metrics, false)
	graph := typedToolArguments()["azure_graph"]
	graph["contextId"] = strings.Repeat("A", 43)
	graph["scope"] = "allAccessible"
	schemaArguments(t, "azure_graph", graph, true)
	graph["scope"] = map[string]any{"scope": "allAccessible"}
	schemaArguments(t, "azure_graph", graph, true)
	graph["subscriptions"] = []string{"11111111-1111-1111-1111-111111111111"}
	schemaArguments(t, "azure_graph", graph, false)
	delete(graph, "scope")
	schemaArguments(t, "azure_graph", graph, true)
}

func TestExportInputPairsOperationArgumentsAndFilenameEncoding(t *testing.T) {
	for name, fields := range typedToolArguments() {
		export := map[string]any{"contextId": strings.Repeat("A", 43), "operation": name, "arguments": fields, "name": "result.json"}
		schemaArguments(t, "azure_export", export, true)
		export["compression"] = "identity"
		schemaArguments(t, "azure_export", export, true)
		export["name"] = "result.json.lz4"
		schemaArguments(t, "azure_export", export, false)
		export["compression"] = "lz4"
		schemaArguments(t, "azure_export", export, true)
		delete(export, "compression")
		schemaArguments(t, "azure_export", export, false)
		export["name"] = "../result.json"
		schemaArguments(t, "azure_export", export, false)
		export["name"] = "result.json"
		fields["contextId"] = strings.Repeat("A", 43)
		schemaArguments(t, "azure_export", export, false)
		delete(fields, "contextId")
		export["operation"] = "azure_accounts"
		schemaArguments(t, "azure_export", export, false)
	}
	export := map[string]any{"contextId": strings.Repeat("A", 43), "operation": "azure_graph", "arguments": typedToolArguments()["azure_request"], "name": "result.json"}
	schemaArguments(t, "azure_export", export, false)
}
