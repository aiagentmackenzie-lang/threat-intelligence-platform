import { z } from "zod";
import { logger } from "../utils/logger.js";

const AIAnalysisSchema = z.object({
  risk: z.enum(["low", "medium", "high", "critical", "unknown"]),
  explanation: z.string(),
  recommendation: z.string(),
});

/**
 * Analyze enriched IOC with LLM
 * @param {Object} ioc - Enriched IOC object
 * @param {Object} llmClient - Optional LLM client (OpenAI compatible)
 * @returns {Promise<Object>} - AI analysis result
 */
export async function analyzeThreat(ioc, llmClient) {
  if (!llmClient && !process.env.OPENAI_API_KEY) {
    return {
      risk: "unknown",
      explanation: "AI analysis disabled - no API key configured",
      recommendation: "Perform manual analyst review",
      aiEnabled: false,
    };
  }

  const prompt = buildAnalysisPrompt(ioc);

  try {
    let response;

    if (llmClient) {
      response = await llmClient.complete({
        prompt,
        response_format: { type: "json_object" },
      });
    } else {
      // Use OpenAI API directly
      response = await callOpenAI(prompt);
    }

    if (!response || !response.text) {
      throw new Error("Empty response from AI");
    }

    // Parse and validate
    const parsedJson = JSON.parse(response.text);
    const validated = AIAnalysisSchema.safeParse(parsedJson);

    if (!validated.success) {
      logger.warn(
        { ioc: ioc.value, errors: validated.error.errors },
        "AI output failed schema validation"
      );
      return {
        risk: "unknown",
        explanation: "AI returned invalid structure",
        recommendation: "Fallback to manual review",
        rawResponse: response.text,
        aiEnabled: true,
      };
    }

    logger.debug(
      { ioc: ioc.value, risk: validated.data.risk },
      "AI analysis complete"
    );

    return {
      ...validated.data,
      aiEnabled: true,
    };
  } catch (error) {
    logger.error({ ioc: ioc.value, error: error.message }, "AI analysis failed");

    return {
      risk: "unknown",
      explanation: "AI analysis failed or returned invalid JSON",
      recommendation: "Fallback to manual review",
      error: error.message,
      aiEnabled: true,
    };
  }
}

/**
 * Build analysis prompt for the LLM
 * @param {Object} ioc - Enriched IOC
 * @returns {string} - Formatted prompt
 */
function buildAnalysisPrompt(ioc) {
  const sections = [
    "You are a SOC analyst analyzing threat intelligence data.",
    "",
    "Analyze the following enriched IOC and provide:",
    "1. Risk level (low, medium, high, critical)",
    "2. Brief explanation of the threat",
    "3. Recommended action",
    "",
    "Return ONLY valid JSON with this exact structure:",
    '{"risk": "low|medium|high|critical", "explanation": "...", "recommendation": "..."}',
    "",
    "IOC Data:",
    `Type: ${ioc.type}`,
    `Value: ${ioc.value}`,
    `Sources: ${ioc.sources?.join(", ") || "unknown"}`,
    `Confidence: ${ioc.confidence || "n/a"}`,
  ];

  if (ioc.attributes?.reputation) {
    sections.push(`Reputation: ${ioc.attributes.reputation}`);
  }
  if (ioc.attributes?.score) {
    sections.push(`Score: ${ioc.attributes.score}`);
  }
  if (ioc.attributes?.country) {
    sections.push(`Country: ${ioc.attributes.country}`);
  }
  if (ioc.attributes?.tags?.length > 0) {
    sections.push(`Tags: ${ioc.attributes.tags.join(", ")}`);
  }

  return sections.join("\n");
}

/**
 * Call OpenAI API directly
 * @param {string} prompt - Analysis prompt
 * @returns {Promise<Object>} - Response object
 */
async function callOpenAI(prompt) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY not configured");
  }

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a cybersecurity analyst. Provide concise, actionable threat intelligence analysis.",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
      response_format: { type: "json_object" },
      max_tokens: 500,
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status}`);
  }

  const data = await response.json();
  return {
    text: data.choices[0]?.message?.content || "",
  };
}

/**
 * Batch analyze multiple IOCs with concurrency control
 * @param {Array} iocs - Array of enriched IOCs
 * @param {Object} llmClient - Optional LLM client
 * @param {Function} limit - p-limit function for concurrency
 * @returns {Promise<Array>} - Array of analyzed IOCs
 */
export async function batchAnalyzeThreats(iocs, llmClient, limit) {
  const results = await Promise.all(
    iocs.map((ioc) =>
      limit(async () => {
        const analysis = await analyzeThreat(ioc, llmClient);
        return {
          ...ioc,
          ...analysis,
        };
      })
    )
  );

  return results;
}
