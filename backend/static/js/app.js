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
    resultsTitle: document.getElementById('results-title'),
    resultsBadge: document.getElementById('results-badge'),
    resultsList: document.getElementById('results-list'),
  };

  // Regular expressions for validation
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const PHONE_REGEX = /^\+?[0-9\s\-\(\)]{7,20}$/;

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

      const rawQuery = elements.searchInput.value ? elements.searchInput.value.trim() : '';
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
      if (mode === 'phone') return 'Please enter a phone number.';
      return 'Please enter a username.';
    }

    if (mode === 'email') {
      if (!EMAIL_REGEX.test(query)) {
        return 'Please enter a valid email address (e.g., user@example.com).';
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
   * Perform backend search via fetch()
   * @param {string} type
   * @param {string} query
   */
  async function performSearch(type, query) {
    setLoadingState(true);

    try {
      const response = await fetch('/api/v1/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ type: type, query: query }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorDetail = data && data.detail ? data.detail : 'Search request failed. Please try again.';
        showError(typeof errorDetail === 'string' ? errorDetail : JSON.stringify(errorDetail));
        return;
      }

      renderResults(data);
    } catch (err) {
      showError('Unable to connect to intelligence backend. Please verify your connection.');
    } finally {
      setLoadingState(false);
    }
  }

  /**
   * Safely render search results without innerHTML injection
   * @param {Object} data
   */
  function renderResults(data) {
    if (!elements.resultsSection || !elements.resultsList) return;

    // Reset results list safely
    while (elements.resultsList.firstChild) {
      elements.resultsList.removeChild(elements.resultsList.firstChild);
    }

    const records = (data && data.records) || [];
    const total = data.total_results || records.length;

    // Update Header
    if (elements.resultsTitle) {
      elements.resultsTitle.textContent = 'Intelligence Findings (' + total + ')';
    }
    if (elements.resultsBadge) {
      elements.resultsBadge.textContent = total > 0 ? 'Verified Matches' : 'No Matches';
    }

    if (records.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.className = 'results-empty';
      emptyDiv.textContent = 'No records located for this identifier.';
      elements.resultsList.appendChild(emptyDiv);
      elements.resultsSection.style.display = 'block';
      return;
    }

    // Render each record using safe DOM methods
    records.forEach(function (rec) {
      const card = document.createElement('div');
      card.className = 'result-card';

      // Header row
      const cardHeader = document.createElement('div');
      cardHeader.className = 'result-card-header';

      const sourceSpan = document.createElement('span');
      sourceSpan.className = 'result-source';
      sourceSpan.textContent = rec.source || 'Intelligence Feed';

      const timeSpan = document.createElement('span');
      timeSpan.className = 'result-timestamp';
      timeSpan.textContent = rec.timestamp || 'Recent';

      cardHeader.appendChild(sourceSpan);
      cardHeader.appendChild(timeSpan);
      card.appendChild(cardHeader);

      // Details grid
      const detailsGrid = document.createElement('div');
      detailsGrid.className = 'result-details';

      // Target item
      const targetItem = document.createElement('div');
      targetItem.className = 'detail-item';
      const targetLabel = document.createElement('span');
      targetLabel.className = 'detail-label';
      targetLabel.textContent = 'Identifier (' + (rec.record_type || 'ID') + ')';
      const targetVal = document.createElement('span');
      targetVal.className = 'detail-value';
      targetVal.textContent = rec.identifier || '';
      targetItem.appendChild(targetLabel);
      targetItem.appendChild(targetVal);
      detailsGrid.appendChild(targetItem);

      // Key-value pairs from details dict
      if (rec.details && typeof rec.details === 'object') {
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
      }

      card.appendChild(detailsGrid);
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
