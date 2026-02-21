package com.lauriewired.mcp.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.victools.jsonschema.generator.Option;
import com.github.victools.jsonschema.generator.OptionPreset;
import com.github.victools.jsonschema.generator.SchemaGeneratorConfig;
import com.github.victools.jsonschema.generator.SchemaGeneratorConfigBuilder;
import com.github.victools.jsonschema.generator.SchemaVersion;
import com.github.victools.jsonschema.module.jackson.JacksonModule;
import com.github.victools.jsonschema.module.jackson.JacksonOption;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.utils.Json;

/**
 * Generates JSON Schema strings from Java record types using victools/jsonschema-generator.
 * Used to derive outputSchema for /mcp/tools at runtime.
 */
public final class SchemaGenerator {
    private static final com.github.victools.jsonschema.generator.SchemaGenerator GENERATOR;

    static {
        final JacksonModule jacksonModule = new JacksonModule(JacksonOption.RESPECT_JSONPROPERTY_REQUIRED);
        final SchemaGeneratorConfigBuilder configBuilder =
            new SchemaGeneratorConfigBuilder(SchemaVersion.DRAFT_2020_12, OptionPreset.PLAIN_JSON)
                .with(jacksonModule)
                .with(Option.FORBIDDEN_ADDITIONAL_PROPERTIES_BY_DEFAULT);
        // Apply snake_case naming to schema properties to match Jackson serialization
        configBuilder.forFields()
            .withPropertyNameOverrideResolver(field ->
                Json.toSnakeCase(field.getDeclaredName()));
        configBuilder.forMethods()
            .withPropertyNameOverrideResolver(method ->
                Json.toSnakeCase(method.getName()));
        final SchemaGeneratorConfig config = configBuilder.build();
        GENERATOR = new com.github.victools.jsonschema.generator.SchemaGenerator(config);
    }

    private SchemaGenerator() {}

    /**
     * Generate a JSON Schema string for a response record type.
     * If outputType is ListOutput, wraps the item schema in a pagination envelope.
     *
     * @param responseType the record type (or Void.class for no schema)
     * @param outputType   the ToolOutput subtype (e.g., ListOutput.class, JsonOutput.class)
     * @return JSON Schema string, or null if responseType is Void
     */
    public static String generateSchema(final Class<?> responseType, final Class<?> outputType) {
        if (responseType == Void.class || responseType == void.class) {
            return null;
        }

        if (outputType == ListOutput.class) {
            // Generate schema for the item type, then wrap in pagination envelope
            final ObjectNode itemSchema = GENERATOR.generateSchema(responseType);
            // Remove $schema from item-level schema (only needed at top level)
            itemSchema.remove("$schema");
            return Json.serialize(buildListEnvelope(itemSchema));
        }

        final ObjectNode schema = GENERATOR.generateSchema(responseType);
        return schema.toString();
    }

    /**
     * Build the pagination envelope schema wrapping item schemas.
     */
    private static Map<String, Object> buildListEnvelope(final ObjectNode itemSchema) {
        final Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("$schema", SchemaVersion.DRAFT_2020_12.getIdentifier());
        schema.put("type", "object");

        final Map<String, Object> properties = new LinkedHashMap<>();

        final Map<String, Object> itemsArray = new LinkedHashMap<>();
        itemsArray.put("type", "array");
        // Convert JsonNode to a Map so Jackson serializes it inline
        itemsArray.put("items", Json.convertValue(itemSchema, Map.class));
        properties.put("items", itemsArray);

        // Nested pagination object
        final Map<String, Object> paginationProps = new LinkedHashMap<>();
        paginationProps.put("remaining", Map.of("type", "integer"));
        paginationProps.put("next_offset", Map.of("type", "integer"));

        final Map<String, Object> paginationObj = new LinkedHashMap<>();
        paginationObj.put("type", "object");
        paginationObj.put("properties", paginationProps);
        paginationObj.put("required", List.of("remaining"));
        paginationObj.put("additionalProperties", false);
        properties.put("pagination", paginationObj);

        schema.put("properties", properties);
        schema.put("required", List.of("items", "pagination"));
        schema.put("additionalProperties", false);
        return schema;
    }
}
