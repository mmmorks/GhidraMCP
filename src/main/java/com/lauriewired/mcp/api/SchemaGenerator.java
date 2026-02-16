package com.lauriewired.mcp.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
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
    private static final PropertyNamingStrategies.SnakeCaseStrategy SNAKE_CASE =
        new PropertyNamingStrategies.SnakeCaseStrategy();

    static {
        JacksonModule jacksonModule = new JacksonModule(JacksonOption.RESPECT_JSONPROPERTY_REQUIRED);
        SchemaGeneratorConfigBuilder configBuilder =
            new SchemaGeneratorConfigBuilder(SchemaVersion.DRAFT_2020_12, OptionPreset.PLAIN_JSON)
                .with(jacksonModule)
                .with(Option.FORBIDDEN_ADDITIONAL_PROPERTIES_BY_DEFAULT);
        // Apply snake_case naming to schema properties to match Jackson serialization
        configBuilder.forFields()
            .withPropertyNameOverrideResolver(field ->
                SNAKE_CASE.translate(field.getDeclaredName()));
        configBuilder.forMethods()
            .withPropertyNameOverrideResolver(method ->
                SNAKE_CASE.translate(method.getName()));
        SchemaGeneratorConfig config = configBuilder.build();
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
    public static String generateSchema(Class<?> responseType, Class<?> outputType) {
        if (responseType == Void.class || responseType == void.class) {
            return null;
        }

        if (outputType == ListOutput.class) {
            // Generate schema for the item type, then wrap in pagination envelope
            JsonNode itemSchema = GENERATOR.generateSchema(responseType);
            // Remove $schema from item-level schema (only needed at top level)
            if (itemSchema instanceof ObjectNode on) {
                on.remove("$schema");
            }
            return Json.serialize(buildListEnvelope(itemSchema));
        }

        JsonNode schema = GENERATOR.generateSchema(responseType);
        return schema.toString();
    }

    /**
     * Build the pagination envelope schema wrapping item schemas.
     */
    private static Map<String, Object> buildListEnvelope(JsonNode itemSchema) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("$schema", SchemaVersion.DRAFT_2020_12.getIdentifier());
        schema.put("type", "object");

        Map<String, Object> properties = new LinkedHashMap<>();

        Map<String, Object> itemsArray = new LinkedHashMap<>();
        itemsArray.put("type", "array");
        // Convert JsonNode to a Map so Jackson serializes it inline
        itemsArray.put("items", Json.mapper().convertValue(itemSchema, Map.class));
        properties.put("items", itemsArray);

        properties.put("total_items", Map.of("type", "integer"));
        properties.put("offset", Map.of("type", "integer"));
        properties.put("limit", Map.of("type", "integer"));
        properties.put("has_more", Map.of("type", "boolean"));

        schema.put("properties", properties);
        schema.put("required", List.of("items", "total_items", "has_more"));
        schema.put("additionalProperties", false);
        return schema;
    }
}
