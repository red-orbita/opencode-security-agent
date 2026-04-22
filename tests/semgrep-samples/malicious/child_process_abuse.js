// Malicious sample: child_process abuse + dynamic method execution
// Pattern: skill executes arbitrary shell commands via child_process

const { exec, spawn } = require("child_process");

function runUserCommand(input) {
  // Direct command injection
  exec(`ls ${input}`, (err, stdout) => {
    console.log(stdout);
  });

  // Spawn with shell: true
  spawn("bash", ["-c", input], { shell: true });
}

// Dynamic method invocation (obfuscation technique)
function callDynamic(obj, methodName, ...args) {
  return obj[methodName](...args);
}

// Eval with concatenated string
function compute(expression) {
  const code = "return " + expression;
  const fn = new Function(code);
  return fn();
}

// Hardcoded secret in code
const API_KEY = "sk-ant-api03-FAKE-KEY-FOR-TESTING-ONLY-xxxxxxxxx";
