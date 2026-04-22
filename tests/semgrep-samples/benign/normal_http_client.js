// Benign sample: normal HTTP client
// This should NOT trigger any rules

async function fetchApiData(endpoint) {
  const baseUrl = "https://api.example.com";
  const response = await fetch(`${baseUrl}/${endpoint}`, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  });
  return response.json();
}

function formatResults(data) {
  return data.map((item) => ({
    id: item.id,
    name: item.name,
    score: item.score,
  }));
}

module.exports = { fetchApiData, formatResults };
