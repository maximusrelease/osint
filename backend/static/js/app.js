/**
 * Cyber Intelligence Frontend Application
 * Vanilla JavaScript implementation for mode selection, validation,
 * API communication, and safe XSS-free DOM rendering.
 */

(function () {
  'use strict';

  // State
  const state = {
    currentMode: 'email',
    isLoading: false,
    activeFilterTool: null,
    lastResultsData: null,
  };

  // DOM Elements cache
  const elements = {
    modeButtons: document.querySelectorAll('.mode-btn'),
    searchForm: document.getElementById('search-form'),
    searchInputBox: document.getElementById('search-input-box'),
    searchInput: document.getElementById('search-input'),
    searchButton: document.getElementById('search-button'),
    btnContent: document.querySelector('.btn-content'),
    btnLoading: document.querySelector('.btn-loading'),
    inlineError: document.getElementById('inline-error'),
    inlineErrorText: document.getElementById('inline-error-text'),
    resultsSection: document.getElementById('results-section'),
    omniscanSuitePanel: document.getElementById('omniscan-suite-panel'),
    omniscanSuiteMeta: document.getElementById('omniscan-suite-meta'),
    omniscanToolsGrid: document.getElementById('omniscan-tools-grid'),
    resultsTitle: document.getElementById('results-title'),
    resultsBadge: document.getElementById('results-badge'),
    resultsList: document.getElementById('results-list'),
  };

  // Regular expressions for validation
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const PHONE_REGEX = /^\+?[0-9\s\-\(\)]{7,20}$/;
  const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

  /**
   * Initialize application
   */
  function initialize() {
    setupModeSelector();
    setupSearchForm();
  }

  /**
   * Setup segmented mode selector buttons
   */
  function setupModeSelector() {
    elements.modeButtons.forEach(function (button) {
      button.addEventListener('click', function () {
        const mode = button.getAttribute('data-mode');
        const placeholder = button.getAttribute('data-placeholder');
        if (!mode || mode === state.currentMode) return;

        // Update active class & accessibility attributes
        elements.modeButtons.forEach(function (btn) {
          btn.classList.remove('active');
          btn.setAttribute('aria-selected', 'false');
        });

        button.classList.add('active');
        button.setAttribute('aria-selected', 'true');

        // Update state and input placeholder
        state.currentMode = mode;
        if (placeholder && elements.searchInput) {
          elements.searchInput.placeholder = placeholder;
        }

        // Clear errors and refocus
        clearError();
        if (elements.searchInput) {
          elements.searchInput.focus();
        }
      });
    });
  }

  /**
   * Setup search form submission & input event listeners
   */
  function setupSearchForm() {
    if (!elements.searchForm) return;

    // Clear error on input change
    elements.searchInput.addEventListener('input', function () {
      clearError();
    });

    // Form submit listener
    elements.searchForm.addEventListener('submit', function (event) {
      event.preventDefault();
      if (state.isLoading) return;

      let rawQuery = elements.searchInput.value ? elements.searchInput.value.trim() : '';

      // Auto-clean domain input if URL was pasted
      if (state.currentMode === 'domain') {
        rawQuery = rawQuery.replace(/^https?:\/\//i, '').split('/')[0].trim();
      }

      const validationError = validateInput(state.currentMode, rawQuery);

      if (validationError) {
        showError(validationError);
        return;
      }

      clearError();
      performSearch(state.currentMode, rawQuery);
    });
  }

  /**
   * Validate user input based on current mode
   * @param {string} mode
   * @param {string} query
   * @returns {string|null} Error message or null
   */
  function validateInput(mode, query) {
    if (!query) {
      if (mode === 'email') return 'Please enter an email address.';
      if (mode === 'domain') return 'Please enter a domain name.';
      if (mode === 'phone') return 'Please enter a phone number.';
      return 'Please enter a username.';
    }

    if (mode === 'email') {
      if (!EMAIL_REGEX.test(query)) {
        return 'Please enter a valid email address (e.g., user@example.com).';
      }
    } else if (mode === 'domain') {
      const clean = query.replace(/^https?:\/\//i, '').split('/')[0].trim();
      if (!DOMAIN_REGEX.test(clean)) {
        return 'Please enter a valid domain name (e.g., example.com).';
      }
    } else if (mode === 'phone') {
      if (!PHONE_REGEX.test(query)) {
        return 'Please enter a valid phone number with 7 to 20 digits.';
      }
    } else if (mode === 'username') {
      if (query.length < 2) {
        return 'Username must be at least 2 characters.';
      }
    }

    return null;
  }

  /**
   * Display inline error message
   * @param {string} message
   */
  function showError(message) {
    if (elements.inlineError && elements.inlineErrorText) {
      elements.inlineErrorText.textContent = message;
      elements.inlineError.style.display = 'flex';
    }
    if (elements.searchInputBox) {
      elements.searchInputBox.classList.add('input-error');
    }
  }

  /**
   * Clear inline error message
   */
  function clearError() {
    if (elements.inlineError && elements.inlineErrorText) {
      elements.inlineErrorText.textContent = '';
      elements.inlineError.style.display = 'none';
    }
    if (elements.searchInputBox) {
      elements.searchInputBox.classList.remove('input-error');
    }
  }

  /**
   * Update button loading state
   * @param {boolean} isLoading
   */
  function setLoadingState(isLoading) {
    state.isLoading = isLoading;
    if (elements.searchButton) {
      elements.searchButton.disabled = isLoading;
    }
    if (elements.btnContent && elements.btnLoading) {
      elements.btnContent.style.display = isLoading ? 'none' : 'inline-flex';
      elements.btnLoading.style.display = isLoading ? 'inline-flex' : 'none';
    }
  }

  /**
   * Perform unified backend search across all active OSINT providers via fetch()
   * @param {string} type
   * @param {string} query
   */
  async function performSearch(type, query) {
    setLoadingState(true);
    state.activeFilterTool = null;

    try {
      const endpoint = '/api/search';
      const requestBody = { type: type, query: query };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorDetail = data && data.detail ? data.detail : 'Search request failed. Please try again.';
        showError(typeof errorDetail === 'string' ? errorDetail : JSON.stringify(errorDetail));
        return;
      }

      renderAggregatedResults(data);
    } catch (err) {
      showError('Unable to connect to intelligence backend. Please verify your connection.');
    } finally {
      setLoadingState(false);
    }
  }

  /**
   * Helper to return emoji icons for OmniScan sub-tools
   */
  function getToolIcon(providerId) {
    if (!providerId) return '⚡';
    const id = providerId.toLowerCase();
    if (id.includes('xposed') || id.includes('breach')) return '🛡️';
    if (id.includes('dns') || id.includes('mail')) return '🌐';
    if (id.includes('disposable') || id.includes('burner') || id.includes('reputation')) return '✉️';
    if (id.includes('threat') || id.includes('feed') || id.includes('intel')) return '📡';
    if (id.includes('phone')) return '📱';
    return '⚡';
  }

  /**
   * Render the OmniScan Multi-Tool Orchestration Deck
   * @param {Object} data
   */
  function renderOmniScanSuite(data) {
    if (!elements.omniscanSuitePanel || !elements.omniscanToolsGrid) return;

    const tools = data.tool_telemetry || [];
    const executionMs = typeof data.execution_time_ms === 'number' ? data.execution_time_ms : 0;
    const totalTools = tools.length;

    // Update Suite Meta
    if (elements.omniscanSuiteMeta) {
      elements.omniscanSuiteMeta.textContent = '';

      const latencyBadge = document.createElement('span');
      latencyBadge.className = 'omniscan-latency-badge';
      latencyBadge.textContent = '⚡ ' + executionMs + ' ms';
      elements.omniscanSuiteMeta.appendChild(latencyBadge);

      const countSpan = document.createElement('span');
      countSpan.textContent = totalTools + ' Tools Executed Concurrently';
      elements.omniscanSuiteMeta.appendChild(countSpan);
    }

    // Clear grid
    while (elements.omniscanToolsGrid.firstChild) {
      elements.omniscanToolsGrid.removeChild(elements.omniscanToolsGrid.firstChild);
    }

    tools.forEach(function (tool) {
      const isSelected = state.activeFilterTool === tool.display_name;
      const chip = document.createElement('div');
      chip.className = 'omniscan-tool-chip' + (isSelected ? ' selected' : '');
      chip.setAttribute('role', 'button');
      chip.setAttribute('tabindex', '0');
      chip.setAttribute('title', 'Click to filter findings by ' + tool.display_name);

      // Top Row (Icon + Name, Latency)
      const topRow = document.createElement('div');
      topRow.className = 'omniscan-tool-top';

      const nameEl = document.createElement('span');
      nameEl.className = 'omniscan-tool-name';
      nameEl.textContent = getToolIcon(tool.provider_id) + ' ' + tool.display_name;
      topRow.appendChild(nameEl);

      const latEl = document.createElement('span');
      latEl.className = 'omniscan-tool-latency';
      latEl.textContent = (tool.execution_time_ms || 0) + ' ms';
      topRow.appendChild(latEl);

      chip.appendChild(topRow);

      // Bottom Row (Status pill)
      const botRow = document.createElement('div');
      botRow.className = 'omniscan-tool-bottom';

      const statusPill = document.createElement('span');
      if (tool.status === 'clean') {
        statusPill.className = 'omniscan-tool-status status-clean';
        statusPill.textContent = '🛡️ 0 Breaches (Clean)';
      } else if (tool.status === 'failed') {
        statusPill.className = 'omniscan-tool-status status-failed';
        statusPill.textContent = '⚠️ ' + (tool.summary || 'Failed');
      } else {
        const count = tool.records_count || 0;
        statusPill.className = 'omniscan-tool-status status-findings';
        statusPill.textContent = '✓ ' + count + ' record' + (count === 1 ? '' : 's');
      }
      botRow.appendChild(statusPill);

      chip.appendChild(botRow);

      // Click to filter by this tool
      chip.addEventListener('click', function () {
        if (state.activeFilterTool === tool.display_name) {
          state.activeFilterTool = null;
        } else {
          state.activeFilterTool = tool.display_name;
        }
        renderAggregatedResults(state.lastResultsData);
      });

      elements.omniscanToolsGrid.appendChild(chip);
    });

    // If an active filter is set, display filter banner with reset option
    if (state.activeFilterTool) {
      const filterBar = document.createElement('div');
      filterBar.className = 'omniscan-filter-bar';
      filterBar.style.gridColumn = '1 / -1';

      const hint = document.createElement('span');
      hint.className = 'omniscan-filter-hint';
      hint.textContent = 'Showing findings filtered by: ' + state.activeFilterTool;
      filterBar.appendChild(hint);

      const resetBtn = document.createElement('button');
      resetBtn.type = 'button';
      resetBtn.className = 'omniscan-filter-reset';
      resetBtn.textContent = 'Show All OmniScan Tools';
      resetBtn.addEventListener('click', function () {
        state.activeFilterTool = null;
        renderAggregatedResults(state.lastResultsData);
      });
      filterBar.appendChild(resetBtn);

      elements.omniscanToolsGrid.appendChild(filterBar);
    }
  }

  /**
   * Safely render aggregated multi-provider intelligence results without innerHTML injection
   * @param {Object} data
   */
  function renderAggregatedResults(data) {
    if (!elements.resultsSection || !elements.resultsList) return;

    state.lastResultsData = data;
    renderOmniScanSuite(data);

    // Reset results list safely
    while (elements.resultsList.firstChild) {
      elements.resultsList.removeChild(elements.resultsList.firstChild);
    }

    elements.resultsBadge.className = 'results-badge';

    const allRecords = (data && data.records) || [];
    const records = state.activeFilterTool
      ? allRecords.filter(function (r) { return r.source === state.activeFilterTool; })
      : allRecords;

    const total = records.length;

    // Check for high-risk / breach presence in records
    const hasBreaches = records.some(function (r) {
      return (
        r.record_type === 'DATA_BREACH' ||
        (r.risk_level && ['High', 'Critical'].includes(r.risk_level))
      );
    });

    // Update Header
    if (elements.resultsTitle) {
      if (state.activeFilterTool) {
        elements.resultsTitle.textContent = state.activeFilterTool + ' (' + total + ')';
      } else {
        elements.resultsTitle.textContent = 'OmniScan Findings (' + total + ')';
      }
    }

    if (elements.resultsBadge) {
      if (hasBreaches) {
        elements.resultsBadge.textContent = 'Exposure Detected (' + total + ' records)';
        elements.resultsBadge.classList.add('badge-danger');
      } else if (total > 0) {
        elements.resultsBadge.textContent = 'Correlated Matches (' + total + ')';
        elements.resultsBadge.classList.add('badge-safe');
      } else {
        elements.resultsBadge.textContent = 'Clean / No Matches';
        elements.resultsBadge.classList.add('badge-safe');
      }
    }

    // Top status banner
    const banner = document.createElement('div');
    banner.className = 'breach-banner ' + (hasBreaches ? 'pwned' : 'clean');

    const bannerIcon = document.createElement('span');
    bannerIcon.className = 'breach-banner-icon';
    bannerIcon.textContent = hasBreaches ? '⚠️' : '🛡️';
    banner.appendChild(bannerIcon);

    const bannerText = document.createElement('span');
    bannerText.textContent = data.message || (hasBreaches
      ? 'Security Warning: Intelligence matches detected across OmniScan tools.'
      : 'Good news: No security alerts or exposures located across active tools.');
    banner.appendChild(bannerText);
    elements.resultsList.appendChild(banner);

    if (records.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.className = 'results-empty';
      emptyDiv.textContent = state.activeFilterTool
        ? 'No records located from ' + state.activeFilterTool + ' for this identifier.'
        : 'No records located across active OmniScan intelligence tools.';
      elements.resultsList.appendChild(emptyDiv);
      elements.resultsSection.style.display = 'block';
      return;
    }

    // Render each record card using safe DOM methods
    records.forEach(function (rec) {
      const card = document.createElement('div');
      card.className = 'result-card ' + (rec.record_type === 'DATA_BREACH' ? 'breach-result' : '');

      // Top Row (Logo/Source, Title, Risk Badge, Timestamp)
      const topRow = document.createElement('div');
      topRow.className = 'result-card-header';

      const leftGroup = document.createElement('div');
      leftGroup.className = 'breach-left-group';

      if (rec.logo_url) {
        const logoImg = document.createElement('img');
        logoImg.className = 'breach-logo';
        logoImg.src = rec.logo_url;
        logoImg.alt = (rec.title || 'Source') + ' logo';
        logoImg.loading = 'lazy';
        logoImg.onerror = function () {
          this.style.display = 'none';
        };
        leftGroup.appendChild(logoImg);
      }

      const titleGroup = document.createElement('div');
      titleGroup.className = 'breach-title-group';

      const titleEl = document.createElement('span');
      titleEl.className = 'breach-name';
      titleEl.textContent = rec.title || rec.source || 'Intelligence Match';
      titleGroup.appendChild(titleEl);

      // OmniScan Engine Card Tag
      const omniTag = document.createElement('span');
      omniTag.className = 'omniscan-card-tag';
      omniTag.textContent = 'OmniScan';
      titleGroup.appendChild(omniTag);

      const sourcePill = document.createElement('span');
      sourcePill.className = 'provider-source-pill';
      sourcePill.textContent = rec.source || 'Provider';
      titleGroup.appendChild(sourcePill);

      leftGroup.appendChild(titleGroup);
      topRow.appendChild(leftGroup);

      // Right metadata (Risk badge + Timestamp)
      const rightGroup = document.createElement('div');
      rightGroup.style.display = 'flex';
      rightGroup.style.alignItems = 'center';
      rightGroup.style.gap = '8px';

      if (rec.risk_level) {
        const riskSpan = document.createElement('span');
        const isHigh = ['High', 'Critical'].includes(rec.risk_level);
        riskSpan.className = 'password-risk-tag ' + (isHigh ? 'high-risk' : 'low-risk');
        riskSpan.textContent = 'Risk: ' + rec.risk_level;
        rightGroup.appendChild(riskSpan);
      }

      if (rec.timestamp) {
        const timeSpan = document.createElement('span');
        timeSpan.className = 'result-timestamp';
        timeSpan.textContent = rec.timestamp;
        rightGroup.appendChild(timeSpan);
      }

      topRow.appendChild(rightGroup);
      card.appendChild(topRow);

      // Description
      if (rec.description) {
        const descEl = document.createElement('p');
        descEl.className = 'breach-description';
        descEl.style.marginTop = '8px';
        descEl.textContent = rec.description;
        card.appendChild(descEl);
      }

      // Details Grid
      if (rec.details && typeof rec.details === 'object' && Object.keys(rec.details).length > 0) {
        const detailsGrid = document.createElement('div');
        detailsGrid.className = 'result-details';

        Object.keys(rec.details).forEach(function (key) {
          const item = document.createElement('div');
          item.className = 'detail-item';

          const label = document.createElement('span');
          label.className = 'detail-label';
          label.textContent = key;

          const val = document.createElement('span');
          val.className = 'detail-value';
          val.textContent = String(rec.details[key]);

          item.appendChild(label);
          item.appendChild(val);
          detailsGrid.appendChild(item);
        });

        card.appendChild(detailsGrid);
      }

      // Tags / Compromised Data Classes
      if (Array.isArray(rec.tags) && rec.tags.length > 0) {
        const tagsWrapper = document.createElement('div');
        tagsWrapper.className = 'breach-dataclasses';

        rec.tags.forEach(function (tag) {
          const pill = document.createElement('span');
          pill.className = 'dataclass-pill';
          const lower = tag.toLowerCase();
          if (lower.includes('password') || lower.includes('credential') || lower.includes('secret')) {
            pill.classList.add('sensitive');
          }
          pill.textContent = tag;
          tagsWrapper.appendChild(pill);
        });

        card.appendChild(tagsWrapper);
      }

      elements.resultsList.appendChild(card);
    });

    elements.resultsSection.style.display = 'block';
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
})();
