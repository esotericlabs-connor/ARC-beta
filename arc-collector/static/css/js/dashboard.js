const state = {
  map: null,
  markers: null,
  summary: window.__ARC_SUMMARY__ || null,
  accounts: window.__ARC_ACCOUNTS__ || [],
};

function initMap() {
  const mapElement = document.getElementById('signin-map');
  if (!mapElement) {
    return;
  }
  state.map = L.map(mapElement, { worldCopyJump: true, zoomControl: false }).setView([20, 0], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
  }).addTo(state.map);
  state.map.addControl(L.control.zoom({ position: 'bottomright' }));
  state.markers = L.layerGroup().addTo(state.map);
  if (state.summary) {
    updateMap(state.summary.geo_points || []);
  }
}

function updateMap(points) {
  if (!state.map || !state.markers) {
    return;
  }
  state.markers.clearLayers();
  const validPoints = (points || []).filter((pt) => pt.latitude && pt.longitude);
  if (!validPoints.length) {
    return;
  }
  const bounds = [];
  validPoints.forEach((pt) => {
    const marker = L.circleMarker([pt.latitude, pt.longitude], {
      radius: 8,
      color: '#4e9af1',
      weight: 2,
      fillColor: '#4e9af1',
      fillOpacity: 0.35,
    });
    const city = pt.city || 'Unknown city';
    const country = pt.country || 'Unknown country';
    const risk = (pt.riskLevel || 'n/a').toUpperCase();
    const user = pt.username || 'unknown user';
    marker.bindPopup(
      `<strong>${user}</strong><br/>${city}, ${country}<br/><span class="risk-label">Risk: ${risk}</span><br/><small>${pt.timestamp}</small>`
    );
    marker.addTo(state.markers);
    bounds.push([pt.latitude, pt.longitude]);
  });
  if (bounds.length === 1) {
    state.map.setView(bounds[0], 6);
  } else if (bounds.length > 1) {
    state.map.fitBounds(bounds, { padding: [40, 40] });
  }
}

function updateSummaryView(summary) {
  state.summary = summary;
  const totalEl = document.getElementById('metric-total-events');
  const riskyEl = document.getElementById('metric-risky-events');
  const atiEl = document.getElementById('metric-ati');
  const connectedEl = document.getElementById('metric-connected');
  if (totalEl) totalEl.textContent = summary.total_events;
  if (riskyEl) riskyEl.textContent = summary.risky_events;
  if (atiEl) atiEl.textContent = summary.adaptive_trust_index.toFixed(1);
  if (connectedEl) connectedEl.textContent = summary.connected_accounts;

  const findingsEl = document.getElementById('security-findings');
  if (findingsEl) {
    findingsEl.innerHTML = '';
    if (!summary.security_findings.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = 'No findings yet. Connect an account to begin analysis.';
      findingsEl.appendChild(li);
    } else {
      summary.security_findings.forEach((finding) => {
        const li = document.createElement('li');
        li.textContent = finding;
        findingsEl.appendChild(li);
      });
    }
  }

  updateMap(summary.geo_points || []);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString(undefined, {
    hour12: false,
  });
}

function renderRiskTag(event) {
  const level = event.signals?.risk_level || 'unknown';
  const anomaly = event.signals?.session_anomaly;
  const tag = document.createElement('span');
  tag.className = 'event-risk-tag';
  tag.dataset.level = level;
  tag.textContent = level.toUpperCase();
  if (anomaly) {
    tag.textContent += ' • Anomaly';
  }
  return tag;
}

function renderEvents(events) {
  const tableBody = document.querySelector('#events-table tbody');
  if (!tableBody) {
    return;
  }
  tableBody.innerHTML = '';
  if (!events.length) {
    const row = document.createElement('tr');
    row.className = 'empty-row';
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.textContent = 'Waiting for events… connect an account or sync to populate data.';
    row.appendChild(cell);
    tableBody.appendChild(row);
    return;
  }

  events
    .slice()
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .forEach((event) => {
      const row = document.createElement('tr');

      const tsCell = document.createElement('td');
      tsCell.textContent = formatDate(event.timestamp);
      row.appendChild(tsCell);

      const providerCell = document.createElement('td');
      providerCell.textContent = event.provider.charAt(0).toUpperCase() + event.provider.slice(1);
      row.appendChild(providerCell);

      const userCell = document.createElement('td');
      userCell.textContent = event.username || event.user_hash;
      row.appendChild(userCell);

      const locationCell = document.createElement('td');
      const geo = event.geo || {};
      const locationParts = [geo.city, geo.region, geo.country].filter(Boolean);
      locationCell.textContent = locationParts.join(', ') || 'Unknown';
      row.appendChild(locationCell);

      const riskCell = document.createElement('td');
      riskCell.appendChild(renderRiskTag(event));
      row.appendChild(riskCell);

      tableBody.appendChild(row);
    });
}

async function fetchJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }
  return response.json();
}

async function refreshSummary() {
  const data = await fetchJSON('/api/summary');
  updateSummaryView(data.summary);
}

async function refreshEvents() {
  const data = await fetchJSON('/api/events');
  renderEvents(data.events || []);
}

async function syncAccount(accountId) {
  await fetchJSON(`/api/accounts/${encodeURIComponent(accountId)}/sync`, { method: 'POST' });
  await Promise.all([refreshSummary(), refreshEvents()]);
}

function bindEvents() {
  const refreshButton = document.getElementById('refresh-events');
  if (refreshButton) {
    refreshButton.addEventListener('click', () => {
      Promise.all([refreshSummary(), refreshEvents()]).catch((error) => console.error(error));
    });
  }

  document.querySelectorAll('[data-sync-account]').forEach((button) => {
    button.addEventListener('click', async (event) => {
      const accountId = event.currentTarget.dataset.syncAccount;
      try {
        event.currentTarget.disabled = true;
        event.currentTarget.textContent = 'Syncing…';
        await syncAccount(accountId);
        event.currentTarget.textContent = 'Synced';
        setTimeout(() => {
          event.currentTarget.textContent = 'Sync now';
          event.currentTarget.disabled = false;
        }, 2000);
      } catch (error) {
        console.error(error);
        event.currentTarget.textContent = 'Error';
        setTimeout(() => {
          event.currentTarget.textContent = 'Sync now';
          event.currentTarget.disabled = false;
        }, 3000);
      }
    });
  });
}

function init() {
  initMap();
  if (state.summary) {
    updateSummaryView(state.summary);
  }
  bindEvents();
  Promise.all([refreshSummary(), refreshEvents()]).catch((error) => console.error(error));
}

document.addEventListener('DOMContentLoaded', init);