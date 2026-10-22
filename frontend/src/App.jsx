
import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://127.0.0.1:8000";

const features = [
  {
    number: "01",
    title: "Attack Path Discovery",
    description:
      "Trace how AI agents can be manipulated, identify root causes, and explore attack sequences.",
    icon: "⌘",
  },
  {
    number: "02",
    title: "Security Testing",
    description:
      "Evaluate agent permissions, tool access, and security controls in a controlled environment.",
    icon: "⛨",
  },
  {
    number: "03",
    title: "Mitigation Analysis",
    description:
      "Apply security controls and retest attack paths to understand their effectiveness.",
    icon: "◇",
  },
  {
    number: "04",
    title: "Resilience Assessment",
    description:
      "Analyze recovery behavior and identify attack branches that need further investigation.",
    icon: "↗",
  },
];

const severityOptions = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

function App() {
  const [apiStatus, setApiStatus] = useState("checking");

  const [attackEvents, setAttackEvents] = useState([]);
  const [attackEventsTotal, setAttackEventsTotal] = useState(0);
  const [attackPaths, setAttackPaths] = useState([]);

  const [securityLoading, setSecurityLoading] = useState(true);
  const [securityError, setSecurityError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [eventSearch, setEventSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  
  useEffect(() => {
  setCurrentPage(1);
}, [severityFilter, eventSearch]);

  // Check backend connectivity.
  useEffect(() => {
    let isMounted = true;

    async function checkApi() {
      try {
        const response = await fetch(`${API_BASE_URL}/health`);

        if (!response.ok) {
          throw new Error("API unavailable");
        }

        const data = await response.json();

        if (isMounted) {
          setApiStatus(
            data.status === "healthy" ? "connected" : "offline"
          );
        }
      } catch {
        if (isMounted) {
          setApiStatus("offline");
        }
      }
    }

    checkApi();

    return () => {
      isMounted = false;
    };
  }, []);

  // Fetch attack events and attack paths.
  useEffect(() => {
    let isMounted = true;

    async function loadSecurityData() {
      try {
        const [eventsResponse, pathsResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/api/attack-events`),
          fetch(`${API_BASE_URL}/api/attack-paths`),
        ]);

        if (!eventsResponse.ok || !pathsResponse.ok) {
          throw new Error("Unable to load security data.");
        }

        const [eventsData, pathsData] = await Promise.all([
          eventsResponse.json(),
          pathsResponse.json(),
        ]);

        const events = Array.isArray(eventsData)
          ? eventsData
          : eventsData.events ?? eventsData.attack_events ?? [];

        const paths = Array.isArray(pathsData)
          ? pathsData
          : pathsData.attack_paths ?? pathsData.paths ?? [];

        if (isMounted) {
          setAttackEvents(events);

          setAttackEventsTotal(
            typeof eventsData.total === "number"
              ? eventsData.total
              : events.length
          );

          setAttackPaths(paths);
          setSecurityError("");
        }
      } catch {
        if (isMounted) {
          setSecurityError(
            "Could not load security data. Please check the backend and retry."
          );
        }
      } finally {
        if (isMounted) {
          setSecurityLoading(false);
        }
      }
    }

    loadSecurityData();

    return () => {
      isMounted = false;
    };
  }, []);

  // Filter events by severity and search term.
  const filteredEvents = attackEvents.filter((event) => {
    const matchesSeverity =
      severityFilter === "ALL" ||
      String(event.severity ?? "").toUpperCase() === severityFilter;

    const searchTerm = eventSearch.trim().toLowerCase();

    const matchesSearch =
      !searchTerm ||
      [
        event.event_id,
        event.event_type,
        event.agent_id,
        event.description,
      ].some((value) =>
        String(value ?? "").toLowerCase().includes(searchTerm)
      );

    return matchesSeverity && matchesSearch;
  });

  const EVENTS_PER_PAGE = 5;
  const [currentPage, setCurrentPage] = useState(1);

  const totalPages = Math.max(
    1,
    Math.ceil(filteredEvents.length / EVENTS_PER_PAGE)
  );

  const displayedEvents = filteredEvents.slice(
    (currentPage - 1) * EVENTS_PER_PAGE,
    currentPage * EVENTS_PER_PAGE
  );

  const severityLevels = [
    { label: "Critical", key: "CRITICAL" },
    { label: "High", key: "HIGH" },
    { label: "Medium", key: "MEDIUM" },
    { label: "Low", key: "LOW" },
    { label: "Info", key: "INFO" },
  ];

  const severityCounts = attackEvents.reduce((counts, event) => {
    const severity = String(
      event.severity ?? "UNKNOWN"
    ).toUpperCase();

    counts[severity] = (counts[severity] ?? 0) + 1;
    return counts;
  }, {});

  const criticalAlerts = severityCounts.CRITICAL ?? 0;
  const highRiskEvents = severityCounts.HIGH ?? 0;

  const otherEvents =
    (severityCounts.MEDIUM ?? 0) +
    (severityCounts.LOW ?? 0) +
    (severityCounts.INFO ?? 0);

  const maxSeverityCount = Math.max(
    1,
    ...severityLevels.map((level) => severityCounts[level.key] ?? 0)
  );

  return (
    <div className="app">
      <header className="navbar">
        <a className="brand" href="#home">
          <span className="brand-icon">A</span>
          <span>
            Agent<span className="brand-accent">Maze</span>
          </span>
        </a>

        <nav className="nav-links">
          <a href="#home">Home</a>
          <a href="#features">Platform</a>
          <a href="#about">About</a>
        </nav>

        <div className={`api-status api-${apiStatus}`}>
          <span className="api-status-dot" />
          {apiStatus === "checking"
            ? "Checking API"
            : apiStatus === "connected"
              ? "API Connected"
              : "API Offline"}
        </div>

        <a className="nav-button" href="#features">
          Explore Platform <span>↗</span>
        </a>
      </header>

      <main>
        {/* Hero section */}
        <section className="hero" id="home">
          <div className="hero-content">
            <div className="eyebrow">
              <span className="live-dot" />
              AI AGENT SECURITY PLATFORM
            </div>

            <h1>
              Explore the hidden
              <br />
              paths of <span>AI attacks.</span>
            </h1>

            <p className="hero-description">
              Discover attack paths, test security controls, and understand
              how autonomous AI agents behave under adversarial conditions.
            </p>

            <div className="hero-actions">
              <a className="primary-button" href="#security-overview">
                Explore the platform <span>→</span>
              </a>

              <a className="secondary-button" href="#about">
                Learn more
              </a>
            </div>

            <div className="hero-note">
              <span className="note-line" />
              CONTROLLED AI SECURITY RESEARCH
            </div>
          </div>

          <div
            className="hero-visual"
            aria-label="AgentMaze security illustration"
          >
            <div className="visual-glow" />
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />

            <div className="central-core">
              <div className="core-symbol">A</div>
              <span>AGENT CORE</span>
            </div>

            <div className="floating-card card-top">
              <div className="mini-card-heading">
                <span>THREAT DETECTION</span>
                <span className="mini-dot" />
              </div>

              <div className="chart-bars">
                {[25, 44, 32, 65, 48, 80, 58, 92].map(
                  (height, index) => (
                    <span
                      key={index}
                      style={{ height: `${height}%` }}
                    />
                  )
                )}
              </div>

              <div className="mini-card-footer">
                Behavioral analysis
              </div>
            </div>

            <div className="floating-card card-bottom">
              <div className="mini-card-heading">
                <span>ATTACK PATH</span>
                <span className="mini-status">TRACE</span>
              </div>

              <div className="mini-flow">
                <span />
                <i />
                <span />
                <i />
                <span className="flow-alert" />
              </div>

              <div className="mini-card-footer">
                Agent → Tool → Risk
              </div>
            </div>

            <div className="visual-caption">
              <span className="caption-dot" />
              AGENT BEHAVIOR ANALYSIS
            </div>
          </div>
        </section>

        {/* Live security overview */}
        <section
          className="security-overview"
          id="security-overview"
        >
          <div className="section-heading">
            <div>
              <div className="eyebrow">LIVE SECURITY DATA</div>
              <h2>Security Overview</h2>
            </div>

            <p>
              Insights from your connected AgentMaze backend.
            </p>
          </div>

          {securityLoading ? (
            <p className="security-message">
              Loading security data...
            </p>
          ) : securityError ? (
            <p className="security-message security-error">
              {securityError}
            </p>
          ) : (
            <>
              <div className="security-stats">
                <article className="security-stat-card">
                  <span>ATTACK EVENTS</span>
                  <strong>{attackEventsTotal}</strong>
                  <small>Total events reported by the API</small>
                </article>

                <article className="security-stat-card">
                  <span>ATTACK PATHS</span>
                  <strong>{attackPaths.length}</strong>
                  <small>Paths returned by the API</small>
                </article>
              </div>

              <div className="severity-chart-panel">
                <div className="severity-chart-heading">
                  <div>
                    <h3>Severity Distribution</h3>
                    <p>Breakdown of loaded attack events by severity</p>
                  </div>

                  <span className="chart-total">
                    {attackEvents.length} events
                  </span>
                </div>

                <div className="severity-summary-grid">
                  <div className="severity-summary-card">
                    <span>CRITICAL ALERTS</span>
                    <strong>{criticalAlerts}</strong>
                    <p>Events requiring immediate attention</p>
                  </div>

                  <div className="severity-summary-card">
                    <span>HIGH-RISK EVENTS</span>
                    <strong>{highRiskEvents}</strong>
                    <p>High-severity events detected</p>
                  </div>

                  <div className="severity-summary-card">
                    <span>OTHER EVENTS</span>
                    <strong>{otherEvents}</strong>
                    <p>Medium, low, and informational events</p>
                  </div>
                </div>

                <div className="severity-chart">
                  {severityLevels.map((level) => {
                    const count = severityCounts[level.key] ?? 0;
                    const percentage = (count / maxSeverityCount) * 100;

                    return (
                      <div className="severity-chart-row" key={level.key}>
                        <div className="severity-chart-label">
                          <span>{level.label}</span>
                          <strong>
                            {count} ·{" "}
                            {attackEvents.length > 0
                              ? ((count / attackEvents.length) * 100).toFixed(1)
                              : "0.0"}
                            %
                          </strong>
                        </div>

                        <div
                          className="severity-bar-track"
                          role="img"
                          aria-label={`${level.label}: ${count} events`}
                        >
                          <div
                            className={`severity-bar severity-bar-${level.key.toLowerCase()}`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <p className="chart-note">
                  Counts are based on events currently returned by the API.
                </p>
              </div>

              {/* Recent attack events */}
              <div className="security-events-panel">
                <div className="security-panel-heading">
                  <h3>Recent Attack Events</h3>
                  <span>{attackEventsTotal} total records</span>
                </div>

                <div
                  className="severity-filters"
                  aria-label="Filter events by severity"
                >
                  <input
                    type="text"
                    className="event-search-input"
                    placeholder="Search by event ID, type, agent, or description..."
                    value={eventSearch}
                    onChange={(e) => {
                      setEventSearch(e.target.value);
                      setCurrentPage(1);
                    }}
                    aria-label="Search attack events"
                  />

                  {severityOptions.map((severity) => (
                    <button
                      key={severity}
                      type="button"
                      className={`severity-filter ${
                        severityFilter === severity ? "active" : ""
                      }`}
                      aria-pressed={severityFilter === severity}
                      onClick={() => {
                        setSeverityFilter(severity);
                        setCurrentPage(1);
                      }}
                    >
                      {severity === "ALL" ? "All Events" : severity}
                    </button>
                  ))}
                </div>

                <p className="security-message">
                  Showing {displayedEvents.length} of{" "}
                  {filteredEvents.length} matching events
                </p>

                {displayedEvents.length === 0 ? (
                  <p className="security-message">
                    No events match your current search and severity filters.
                  </p>
                ) : (
                  <div className="security-event-list">
                    {displayedEvents.map((event, index) => {
                      const severity = String(
                        event.severity ?? "unknown"
                      ).toLowerCase();

                      return (
                        <article
                          className="security-event security-event-clickable"
                          key={event.event_id ?? index}
                          role="button"
                          tabIndex={0}
                          aria-label={`View details for ${event.event_type ?? "security event"}`}
                          onClick={() => setSelectedEvent(event)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              setSelectedEvent(event);
                            }
                          }}
                        >
                          <span className="event-indicator" />

                          <div className="security-event-content">
                            <div className="event-title-row">
                              <strong>
                                {event.event_type ?? "Security Event"}
                              </strong>

                              <span
                                className={`severity-badge severity-${severity}`}
                              >
                                {event.severity ?? "UNKNOWN"}
                              </span>
                            </div>

                            <p>
                              {event.description ??
                                "No description available."}
                            </p>

                            <small className="event-meta">
                              {event.agent_id ?? "Unknown agent"} ·{" "}
                              {event.severity ?? "Unknown severity"}
                            </small>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                )}

                {filteredEvents.length > EVENTS_PER_PAGE && (
                  <div className="event-pagination" aria-label="Event pages">
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() =>
                        setCurrentPage((page) => Math.max(1, page - 1))
                      }
                      disabled={currentPage === 1}
                    >
                      Previous
                    </button>
                    <span aria-live="polite">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() =>
                        setCurrentPage((page) => Math.min(totalPages, page + 1))
                      }
                      disabled={currentPage === totalPages}
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>

              {/* Recent attack paths */}
              <div className="security-events-panel">
                <div className="security-panel-heading">
                  <h3>Recent Attack Paths</h3>
                  <span>{attackPaths.length} records</span>
                </div>

                {attackPaths.length === 0 ? (
                  <p className="security-message">
                    No attack paths were returned by the API.
                  </p>
                ) : (
                  <div className="security-event-list">
                    {attackPaths.slice(0, 5).map((path, index) => (
                      <article
                        className="security-event"
                        key={path.id ?? path.path_id ?? index}
                      >
                        <span className="event-indicator" />

                        <div className="security-event-content">
                          <strong>
                            {path.name ??
                              path.title ??
                              path.path_type ??
                              path.type ??
                              `Attack Path ${index + 1}`}
                          </strong>

                          <p>
                            {path.description ??
                              path.summary ??
                              path.attack_path ??
                              "Attack path recorded by AgentMaze."}
                          </p>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>

              {/* Event details modal */}
              {selectedEvent && (
                <div
                  className="event-details-backdrop"
                  role="presentation"
                  onClick={(e) => {
                    if (e.target === e.currentTarget) {
                      setSelectedEvent(null);
                    }
                  }}
                >
                  <section
                    className="event-details-modal"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="event-details-title"
                  >
                    <div className="event-details-heading">
                      <div>
                        <span className="eyebrow">EVENT INSPECTION</span>
                        <h3 id="event-details-title">
                          {selectedEvent.event_type ?? "Security Event"}
                        </h3>
                      </div>

                      <button
                        type="button"
                        className="event-details-close"
                        onClick={() => setSelectedEvent(null)}
                        aria-label="Close event details"
                      >
                        ×
                      </button>
                    </div>

                    <div className="event-details-summary">
                      <span
                        className={`severity-badge severity-${String(
                          selectedEvent.severity ?? "unknown"
                        ).toLowerCase()}`}
                      >
                        {selectedEvent.severity ?? "UNKNOWN"}
                      </span>

                      <span className="event-details-id">
                        ID: {selectedEvent.event_id ?? "Not provided"}
                      </span>
                    </div>

                    <p className="event-details-description">
                      {selectedEvent.description ??
                        "No description available."}
                    </p>

                    <div className="event-details-grid">
                      {[
                        ["Timestamp", selectedEvent.timestamp],
                        ["Agent ID", selectedEvent.agent_id],
                        ["Source", selectedEvent.source],
                        ["Target", selectedEvent.target],
                        ["Relation", selectedEvent.relation],
                      ].map(([label, value]) => (
                        <div className="event-detail-field" key={label}>
                          <span>{label}</span>
                          <strong>
                            {value === undefined ||
                            value === null ||
                            value === ""
                              ? "Not provided"
                              : String(value)}
                          </strong>
                        </div>
                      ))}
                    </div>

                    <div className="event-detail-related">
                      <h4>Related Event IDs</h4>

                      {Array.isArray(selectedEvent.parent_event_ids) &&
                      selectedEvent.parent_event_ids.length > 0 ? (
                        <div className="event-related-list">
                          {selectedEvent.parent_event_ids.map((id, index) => (
                            <span key={`${String(id)}-${index}`}>
                              {String(id)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p>
                          No related event IDs provided for this event.
                        </p>
                      )}
                    </div>

                    <div className="event-details-actions">
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => setSelectedEvent(null)}
                      >
                        Close details
                      </button>
                    </div>
                  </section>
                </div>
              )}
            </>
          )}
        </section>

        {/* Platform information */}
        <section className="platform-strip" id="about">
          <div>
            <span className="strip-label">BUILT FOR</span>
            <strong>AI Security Research</strong>
          </div>

          <div>
            <span className="strip-label">FOCUS</span>
            <strong>Adversarial Testing</strong>
          </div>

          <div>
            <span className="strip-label">APPROACH</span>
            <strong>Evidence-Based Analysis</strong>
          </div>
        </section>

        {/* Feature cards */}
        <section className="features-section" id="features">
          <div className="section-heading">
            <div>
              <div className="eyebrow">THE PLATFORM</div>
              <h2>Understand. Test. Strengthen.</h2>
            </div>

            <p>
              A controlled environment for investigating the security and
              resilience of AI-agent systems.
            </p>
          </div>

          <div className="features-grid">
            {features.map((feature) => (
              <article
                className="feature-card"
                key={feature.number}
              >
                <div className="feature-top">
                  <span className="feature-number">
                    {feature.number}
                  </span>

                  <span className="feature-icon">
                    {feature.icon}
                  </span>
                </div>

                <h3>{feature.title}</h3>
                <p>{feature.description}</p>

                <a
                  href="#security-overview"
                  aria-label={`Explore ${feature.title}`}
                >
                  Explore <span>↗</span>
                </a>
              </article>
            ))}
          </div>
        </section>
      </main>

      <footer className="footer">
        <a className="brand footer-brand" href="#home">
          <span className="brand-icon">A</span>
          <span>
            Agent<span className="brand-accent">Maze</span>
          </span>
        </a>

        <span>AI AGENT SECURITY · CONTROLLED RESEARCH</span>
        <span>DEVELOPMENT BUILD</span>
      </footer>
    </div>
  );
}

export default App;
