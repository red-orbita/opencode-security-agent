// Benign sample: legitimate TypeScript skill
// This should NOT trigger any rules

interface SkillConfig {
  name: string;
  version: string;
  description: string;
}

function validateConfig(config: SkillConfig): boolean {
  if (!config.name || config.name.length === 0) return false;
  if (!config.version.match(/^\d+\.\d+\.\d+$/)) return false;
  return true;
}

async function processInput(text: string): Promise<string> {
  const words = text.split(/\s+/);
  const wordCount = words.length;
  const charCount = text.length;
  return `Words: ${wordCount}, Characters: ${charCount}`;
}

export { validateConfig, processInput };
