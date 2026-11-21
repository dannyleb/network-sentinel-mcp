package tools

// Input schemas are written out rather than inferred from the input structs, so
// every limit (ranges, lengths, allowed values) is explicit and visible to the
// client. The SDK validates each call against its schema before the handler
// runs; handlers re-check the same limits in their normalize methods.
// TestEveryToolIsReadOnlyAndBounded keeps each schema in step with its input
// struct.
//
// Defaults are stated in descriptions and applied by normalize, not declared
// with "default": go-sdk v1.8.0 panics when a client sends "arguments": null
// to a tool whose schema has defaults (it fills defaults into a nil map).

type schema = map[string]any

func object(props schema, required ...string) schema {
	s := schema{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func integer(description string, lo, hi int) schema {
	return schema{"type": "integer", "description": description, "minimum": lo, "maximum": hi}
}

func text(description string, maxLen int, pattern string) schema {
	s := schema{"type": "string", "description": description, "maxLength": maxLen}
	if pattern != "" {
		s["pattern"] = pattern
	}
	return s
}
