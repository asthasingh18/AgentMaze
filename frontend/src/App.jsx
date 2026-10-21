
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

  // Filter events by severity.
  const filteredEvents = attackEvents.filter((event) => {
    if (severityFilter === "ALL") {
      return true;
    }

    return (
      String(event.severity ?? "").toUpperCase() === severityFilter
    );
  });

  const displayedEvents = filteredEvents.slice(0, 5);
  
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
                  {severityOptions.map((severity) => (
                    <button
                      key={severity}
                      type="button"
                      className={`severity-filter ${
                        severityFilter === severity ? "active" : ""
                      }`}
                      aria-pressed={severityFilter === severity}
                      onClick={() => setSeverityFilter(severity)}
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
                    No events found for this severity.
                  </p>
                ) : (
                  <div className="security-event-list">
                    {displayedEvents.map((event, index) => {
                      const severity = String(
                        event.severity ?? "unknown"
                      ).toLowerCase();

                      return (
                        <article
                          className="security-event"
                          key={event.event_id ?? index}
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
