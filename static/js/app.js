let mapInstance = null;
let hopMarkers = [];
let routePolyline = null;
let currentReportData = null;
let selectedFile = null;
let selectedSourceName = "pasted-email.eml";
let lenis = null;
let portalScene = null;

document.addEventListener("DOMContentLoaded", () => {
    initLenis();
    initCyberCanvas();
    initSpotlights();
    initMap();
    loadSampleList();
    initPortal3D();
    initAIMathToggle();
    
    document.getElementById("btn-analyze").addEventListener("click", runAnalysis);
    document.getElementById("btn-export-pdf").addEventListener("click", exportPDF);
    document.getElementById("email-file").addEventListener("change", handleFileSelection);
    document.getElementById("email-input").addEventListener("input", () => {
        if (document.getElementById("email-input").value.trim()) {
            selectedFile = null;
            selectedSourceName = "pasted-email.eml";
            document.getElementById("email-file").value = "";
            clearActiveSampleButtons();
            setText("file-status", "Using pasted RFC-822 content.");
        }
    });
});

function clearActiveSampleButtons() {
    document.querySelectorAll(".btn-sample").forEach((btn) => btn.classList.remove("active"));
}

/* ==========================================================================
   1. Lenis Smooth Scrolling
   ========================================================================== */
function initLenis() {
    if (typeof window.Lenis !== "undefined") {
        try {
            lenis = new Lenis({
                duration: 1.2,
                easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
                smoothWheel: true,
                touchMultiplier: 1.5,
            });

            function raf(time) {
                lenis.raf(time);
                requestAnimationFrame(raf);
            }
            requestAnimationFrame(raf);
        } catch (e) {
            console.warn("Lenis init fallback:", e);
        }
    }
}

/* ==========================================================================
   2. Lusion-Inspired 3D Quantum Portal Sequence (Three.js)
   ========================================================================== */
function initPortal3D() {
    const canvas = document.getElementById("portal-canvas");
    if (!canvas || !window.THREE) return;

    const overlay = document.getElementById("portal-overlay");
    const skipBtn = document.getElementById("btn-skip-portal");

    let width = window.innerWidth;
    let height = window.innerHeight;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x020612, 0.0018);

    const camera = new THREE.PerspectiveCamera(70, width / height, 0.1, 2000);
    camera.position.z = 100;

    let renderer;
    try {
        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
        renderer.setSize(width, height);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    } catch (err) {
        console.warn("Three.js WebGL init fallback:", err);
        return;
    }

    window.addEventListener("resize", () => {
        width = window.innerWidth;
        height = window.innerHeight;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height);
    });

    // 1. Hyperspace Warp Tunnel Particles
    const particleCount = 1800;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const cyanColor = new THREE.Color(0x00f0ff);
    const violetColor = new THREE.Color(0x818cf8);
    const goldColor = new THREE.Color(0xfbbf24);

    for (let i = 0; i < particleCount; i++) {
        const radius = Math.random() * 80 + 15;
        const theta = Math.random() * Math.PI * 2;
        const z = (Math.random() - 0.5) * 1600;

        positions[i * 3] = radius * Math.cos(theta);
        positions[i * 3 + 1] = radius * Math.sin(theta);
        positions[i * 3 + 2] = z;

        const mixRatio = Math.random();
        let particleColor;
        if (mixRatio < 0.6) particleColor = cyanColor;
        else if (mixRatio < 0.85) particleColor = violetColor;
        else particleColor = goldColor;

        colors[i * 3] = particleColor.r;
        colors[i * 3 + 1] = particleColor.g;
        colors[i * 3 + 2] = particleColor.b;
    }

    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));

    const particleMaterial = new THREE.PointsMaterial({
        size: 2.8,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
    });

    const particleSystem = new THREE.Points(geometry, particleMaterial);
    scene.add(particleSystem);

    // 2. Holographic 3D Digital Mail Packet
    const packetGroup = new THREE.Group();

    // Envelope wireframe box
    const boxGeo = new THREE.BoxGeometry(22, 14, 2.5);
    const boxEdges = new THREE.EdgesGeometry(boxGeo);
    const boxLine = new THREE.LineSegments(
        boxEdges,
        new THREE.LineBasicMaterial({ color: 0x00f0ff, linewidth: 2 })
    );
    packetGroup.add(boxLine);

    // Envelope flap wireframe lines
    const flapPoints = [
        new THREE.Vector3(-11, 7, 1.3),
        new THREE.Vector3(0, -1.5, 1.3),
        new THREE.Vector3(11, 7, 1.3),
    ];
    const flapGeo = new THREE.BufferGeometry().setFromPoints(flapPoints);
    const flapLine = new THREE.Line(
        flapGeo,
        new THREE.LineBasicMaterial({ color: 0x818cf8, linewidth: 2 })
    );
    packetGroup.add(flapLine);

    // Glowing core crystal
    const coreGeo = new THREE.OctahedronGeometry(3.5, 0);
    const coreMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.7,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    packetGroup.add(coreMesh);

    packetGroup.position.set(0, 0, 30);
    scene.add(packetGroup);

    // 3. Glowing Portal Rings (4 Relays)
    const portalRings = [];
    const ringZPositions = [-250, -600, -950, -1300];
    const ringColors = [0x00f0ff, 0x818cf8, 0xfbbf24, 0x34d399];

    ringZPositions.forEach((zPos, index) => {
        const ringGeo = new THREE.TorusGeometry(50, 1.2, 16, 64);
        const ringMat = new THREE.MeshBasicMaterial({
            color: ringColors[index],
            wireframe: true,
            transparent: true,
            opacity: 0.6,
        });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.position.set(0, 0, zPos);
        scene.add(ringMesh);
        portalRings.push(ringMesh);
    });

    let isPlaying = false;
    let animationId = null;
    let sequenceCallback = null;
    let startTime = 0;
    const duration = 2400; // 2.4 seconds

    function animatePortal(time) {
        if (!startTime) startTime = time;
        const elapsed = time - startTime;
        const progress = Math.min(elapsed / duration, 1);

        const posArray = particleSystem.geometry.attributes.position.array;
        const speed = 12 + progress * 24;

        for (let i = 0; i < particleCount; i++) {
            posArray[i * 3 + 2] += speed;
            if (posArray[i * 3 + 2] > 200) {
                posArray[i * 3 + 2] = -1400;
            }
        }
        particleSystem.geometry.attributes.position.needsUpdate = true;

        packetGroup.rotation.y = Math.sin(time * 0.003) * 0.25;
        packetGroup.rotation.x = Math.cos(time * 0.002) * 0.15;
        packetGroup.rotation.z = Math.sin(time * 0.004) * 0.1;
        coreMesh.rotation.x += 0.03;
        coreMesh.rotation.y += 0.04;

        portalRings.forEach((ring, idx) => {
            ring.rotation.z += 0.01 * (idx % 2 === 0 ? 1 : -1);
            ring.position.z += speed * 0.8;
            if (ring.position.z > 150) {
                ring.position.z = -1400;
            }
        });

        const progressPercent = Math.round(progress * 100);
        const fill = document.getElementById("portal-progress-fill");
        if (fill) fill.style.width = `${progressPercent}%`;

        const stepEl = document.getElementById("portal-status-step");
        const t1 = document.getElementById("telemetry-line-1");
        const t2 = document.getElementById("telemetry-line-2");

        if (progress < 0.25) {
            if (stepEl) stepEl.textContent = "INGESTING RFC-5322 DATA ENVELOPE...";
            if (t1) t1.textContent = "> EVIDENCE LOCK: SHA-256 INTEGRITY COMPUTED";
            if (t2) t2.textContent = "> EXTRACTING MIME BOUNDARIES & RECEIVED HEADERS...";
        } else if (progress < 0.5) {
            if (stepEl) stepEl.textContent = "AUDITING CRYPTOGRAPHIC SIGNATURES (SPF / DKIM)...";
            if (t1) t1.textContent = "> QUERYING DNS TXT RECORDS FOR SENDER POLICY (SPF)...";
            if (t2) t2.textContent = "> VALIDATING RSA/Ed25519 HEADER & BODY HASHES (DKIM)...";
        } else if (progress < 0.75) {
            if (stepEl) stepEl.textContent = "TRACING AUTONOMOUS RELAY INFRASTRUCTURE...";
            if (t1) t1.textContent = "> EVALUATING HOP TIME VECTOR (ΔT CHRONOLOGY)...";
            if (t2) t2.textContent = "> GEOLOCATING CANDIDATE SOURCE MTA IP NODES...";
        } else {
            if (stepEl) stepEl.textContent = "MULTINOMIAL NAIVE BAYES NEURAL CLASSIFICATION...";
            if (t1) t1.textContent = "> VECTORIZING SEMANTIC TOKENS & LOG-ODDS RATIOS...";
            if (t2) t2.textContent = "> APPENDING TAMPER-PROOF EVIDENCE LEDGER...";
        }

        renderer.render(scene, camera);

        if (progress < 1 && isPlaying) {
            animationId = requestAnimationFrame(animatePortal);
        } else if (isPlaying) {
            finishPortal();
        }
    }

    function startSequence(sourceName, callback) {
        sequenceCallback = callback;
        isPlaying = true;
        startTime = 0;

        const packetIdEl = document.getElementById("portal-packet-id");
        if (packetIdEl) packetIdEl.textContent = sourceName || "RFC-5322://EMAIL-EVIDENCE";

        overlay.hidden = false;
        overlay.classList.remove("fading-out");

        animationId = requestAnimationFrame(animatePortal);
    }

    function finishPortal() {
        if (!isPlaying) return;
        isPlaying = false;
        if (animationId) cancelAnimationFrame(animationId);

        overlay.classList.add("fading-out");
        window.setTimeout(() => {
            overlay.hidden = true;
            overlay.classList.remove("fading-out");
            if (sequenceCallback) {
                const cb = sequenceCallback;
                sequenceCallback = null;
                cb();
            }
        }, 550);
    }

    if (skipBtn) {
        skipBtn.addEventListener("click", finishPortal);
    }

    window.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && isPlaying) {
            finishPortal();
        }
    });

    portalScene = {
        play: startSequence,
        finish: finishPortal,
    };
}

/* ==========================================================================
   3. Interactive Kinetic Cyber Constellation Canvas (Background)
   ========================================================================== */
function initCyberCanvas() {
    const canvas = document.getElementById("cyber-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    let mouse = { x: -1000, y: -1000, radius: 140 };

    window.addEventListener("resize", () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    window.addEventListener("mousemove", (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    window.addEventListener("mouseleave", () => {
        mouse.x = -1000;
        mouse.y = -1000;
    });

    const particleCount = Math.min(65, Math.floor((width * height) / 22000));
    const particles = [];

    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 0.45;
            this.vy = (Math.random() - 0.5) * 0.45;
            this.size = Math.random() * 1.6 + 0.8;
            this.baseAlpha = Math.random() * 0.4 + 0.2;
            this.alpha = this.baseAlpha;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0) this.x = width;
            if (this.x > width) this.x = 0;
            if (this.y < 0) this.y = height;
            if (this.y > height) this.y = 0;

            const dx = mouse.x - this.x;
            const dy = mouse.y - this.y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < mouse.radius) {
                const force = (mouse.radius - dist) / mouse.radius;
                const angle = Math.atan2(dy, dx);
                this.x -= Math.cos(angle) * force * 1.5;
                this.y -= Math.sin(angle) * force * 1.5;
                this.alpha = Math.min(0.9, this.baseAlpha + 0.4);
            } else {
                this.alpha = this.baseAlpha;
            }
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 240, 255, ${this.alpha})`;
            ctx.shadowBlur = 8;
            ctx.shadowColor = "rgba(0, 240, 255, 0.5)";
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        for (let i = 0; i < particles.length; i++) {
            particles[i].update();
            particles[i].draw();

            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 110) {
                    const lineAlpha = (1 - dist / 110) * 0.18;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 240, 255, ${lineAlpha})`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(animate);
    }

    animate();
}

/* ==========================================================================
   4. BDSN Spotlight Cursor Tracker
   ========================================================================== */
function initSpotlights() {
    let ticking = false;

    window.addEventListener("mousemove", (e) => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const elements = document.querySelectorAll(".card, .btn-primary, .btn-secondary, .btn-sample, .protocol-card");
                const clientX = e.clientX;
                const clientY = e.clientY;

                elements.forEach((el) => {
                    const rect = el.getBoundingClientRect();
                    if (
                        clientX >= rect.left - 80 &&
                        clientX <= rect.right + 80 &&
                        clientY >= rect.top - 80 &&
                        clientY <= rect.bottom + 80
                    ) {
                        const x = clientX - rect.left;
                        const y = clientY - rect.top;
                        el.style.setProperty("--mouse-x", `${x}px`);
                        el.style.setProperty("--mouse-y", `${y}px`);
                    }
                });
                ticking = false;
            });
            ticking = true;
        }
    });
}

/* ==========================================================================
   5. Collapsible AI Technical Math Toggle for Judges
   ========================================================================== */
function initAIMathToggle() {
    const btn = document.getElementById("btn-toggle-ai-math");
    const breakdown = document.getElementById("ai-math-breakdown");
    const icon = document.getElementById("ai-toggle-icon");
    const textEl = document.getElementById("ai-toggle-text");
    if (!btn || !breakdown) return;

    btn.addEventListener("click", () => {
        const isHidden = breakdown.hidden;
        breakdown.hidden = !isHidden;
        if (icon) icon.textContent = isHidden ? "▴" : "▾";
        if (textEl) textEl.textContent = isHidden ? "Hide Model Details" : "How the AI Model Works";
    });
}

/* ==========================================================================
   6. Smooth Digital Roll-Up Counter
   ========================================================================== */
function animateValue(id, start, end, duration = 1000, formatter = null) {
    const obj = document.getElementById(id);
    if (!obj) return;
    if (isNaN(end)) {
        obj.textContent = end ?? "--";
        return;
    }

    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const easeProgress = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
        const current = start + (end - start) * easeProgress;

        if (formatter) {
            obj.textContent = formatter(current);
        } else {
            obj.textContent = Math.round(current);
        }

        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value ?? "--";
}

/* ==========================================================================
   7. Leaflet Geographic Map
   ========================================================================== */
function initMap() {
    const fallback = document.getElementById("map-fallback");
    if (!window.L) {
        if (fallback) fallback.textContent = "Interactive map unavailable. Relay evidence remains visible in the table.";
        return;
    }
    if (fallback) fallback.remove();
    mapInstance = L.map("map", { zoomControl: true }).setView([20.5937, 78.9629], 3);
    const layer = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: "&copy; OpenStreetMap &copy; CARTO",
        maxZoom: 18,
    });
    layer.on("tileerror", () => document.getElementById("map")?.classList.add("tiles-unavailable"));
    layer.addTo(mapInstance);
}

/* ==========================================================================
   8. Demonstration Scenario Samples
   ========================================================================== */
async function loadSampleList() {
    const container = document.getElementById("sample-buttons-container");
    try {
        const response = await fetch("/api/samples");
        if (!response.ok) throw new Error("Sample list unavailable");
        const data = await response.json();
        container.replaceChildren();
        data.samples.forEach((sample) => {
            const button = document.createElement("button");
            button.className = "btn-sample";
            button.type = "button";
            button.textContent = sample.replace(".eml", "").replaceAll("_", " ").toUpperCase();
            button.addEventListener("click", () => {
                clearActiveSampleButtons();
                button.classList.add("active");
                loadSample(sample);
            });
            container.appendChild(button);
        });
    } catch (error) {
        container.textContent = "Demonstration samples unavailable";
    }
}

async function loadSample(sampleName) {
    clearError();
    try {
        const response = await fetch(`/api/sample/${encodeURIComponent(sampleName)}`);
        if (!response.ok) throw new Error("Unable to load demonstration sample");
        const data = await response.json();
        selectedFile = null;
        selectedSourceName = sampleName;
        document.getElementById("email-file").value = "";
        document.getElementById("email-input").value = data.content;
        setText("file-status", `Controlled demonstration sample: ${sampleName}`);
        await runAnalysis();
    } catch (error) {
        showError(error.message);
    }
}

function handleFileSelection(event) {
    clearError();
    clearActiveSampleButtons();
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
        event.target.value = "";
        selectedFile = null;
        showError("The selected email exceeds the 5 MB prototype limit.");
        return;
    }
    selectedFile = file;
    selectedSourceName = file.name;
    document.getElementById("email-input").value = "";
    setText("file-status", `Selected: ${file.name} • ${(file.size / 1024).toFixed(1)} KB`);
    event.target.value = "";
}

/* ==========================================================================
   9. Core Analysis Runner with Lusion 3D Portal Transition
   ========================================================================== */
async function runAnalysis() {
    const rawText = document.getElementById("email-input").value.trim();
    if (!selectedFile && !rawText) {
        showError("Upload an .eml file, paste raw email content, or select a demonstration scenario.");
        return;
    }

    clearError();
    setLoading(true);

    const executeBackendAnalysis = async () => {
        const formData = new FormData();
        if (rawText) {
            formData.append("raw_text", rawText);
            formData.append("source_name", selectedSourceName || "pasted-email.eml");
        } else if (selectedFile) {
            formData.append("file", selectedFile);
            formData.append("source_name", selectedFile.name);
        }

        const response = await fetch("/api/analyze", { method: "POST", body: formData });
        if (!response.ok) {
            const errorBody = await response.json().catch(() => ({}));
            throw new Error(errorBody.detail || `Analysis failed (${response.status})`);
        }
        return await response.json();
    };

    try {
        const apiPromise = executeBackendAnalysis();

        if (portalScene) {
            portalScene.play(selectedSourceName, async () => {
                try {
                    currentReportData = await apiPromise;
                    renderDashboard(currentReportData);
                } catch (err) {
                    showError(err.message);
                } finally {
                    setLoading(false);
                }
            });
        } else {
            currentReportData = await apiPromise;
            renderDashboard(currentReportData);
            setLoading(false);
        }
    } catch (error) {
        showError(error.message);
        setLoading(false);
    }
}

function setLoading(isLoading) {
    document.getElementById("loading-section").hidden = !isLoading;
    const button = document.getElementById("btn-analyze");
    button.disabled = isLoading;
    const btnText = button.querySelector(".btn-text");
    if (btnText) {
        btnText.textContent = isLoading ? "Analyzing…" : "Run analysis";
    } else {
        button.textContent = isLoading ? "Analyzing…" : "Run analysis";
    }
}

function showError(message) {
    const element = document.getElementById("error-message");
    element.textContent = message;
    element.hidden = false;
}

function clearError() {
    const element = document.getElementById("error-message");
    element.textContent = "";
    element.hidden = true;
}

/* ==========================================================================
   10. Dashboard Renderer & Front-and-Center AI + Auth Deep Dive
   ========================================================================== */
function renderDashboard(data) {
    const results = document.getElementById("results-section");
    results.hidden = false;
    setText("result-filename", data.input_metadata?.filename || "Submitted email");
    setText("analysis-id", data.analysis_id);

    const threat = data.threat_analysis || {};
    const targetScore = Number(threat.threat_score ?? 0);
    
    // 1. Composite Risk Roll-up & SVG Gauge Arc
    animateValue("threat-score-val", 0, targetScore, 1200);

    const gaugeBar = document.getElementById("gauge-bar");
    if (gaugeBar) {
        const circumference = 314.16;
        const offset = Math.max(0, circumference - (circumference * targetScore) / 100);
        
        let strokeColor = "#00f0ff";
        if (targetScore >= 70) strokeColor = "#f43f5e";
        else if (targetScore >= 40) strokeColor = "#fbbf24";
        else strokeColor = "#34d399";
        
        gaugeBar.style.stroke = strokeColor;
        gaugeBar.style.filter = `drop-shadow(0 0 8px ${strokeColor})`;
        gaugeBar.style.strokeDashoffset = circumference;
        
        window.requestAnimationFrame(() => {
            gaugeBar.style.strokeDashoffset = offset;
        });
    }

    const safeColor = /^#[0-9A-F]{6}$/i.test(threat.badge_color || "") ? threat.badge_color : "#fbbf24";
    const verdict = document.getElementById("verdict-badge");
    verdict.textContent = threat.verdict || "REVIEW REQUIRED";
    verdict.style.color = safeColor;
    verdict.style.borderColor = safeColor;
    verdict.style.backgroundColor = `${safeColor}1F`;
    verdict.style.boxShadow = `0 0 12px ${safeColor}33`;

    // 2. Summary Grid Standard Cards
    const ml = data.ml_analysis || {};
    const mlProbability = Number(ml.phishing_probability);
    if (Number.isFinite(mlProbability)) {
        animateValue("ml-probability", 0, mlProbability * 100, 1100, (v) => `${v.toFixed(1)}%`);
    } else {
        setText("ml-probability", "--");
    }
    setText("ml-label", `${ml.label || "UNCERTAIN"} • demonstration corpus`);

    // Authentication summary card color-coded
    const auth = data.authentication || {};
    const overall = auth.overall_status || "UNVERIFIED";
    const authOverallEl = document.getElementById("auth-overall");
    if (authOverallEl) {
        authOverallEl.textContent = overall.replaceAll("_", " ");
        if (overall.includes("PASS")) {
            authOverallEl.style.color = "var(--green)";
            authOverallEl.style.textShadow = "0 0 15px rgba(52, 211, 153, 0.4)";
        } else if (overall.includes("FAIL")) {
            authOverallEl.style.color = "var(--red)";
            authOverallEl.style.textShadow = "0 0 15px rgba(244, 63, 94, 0.4)";
        } else {
            authOverallEl.style.color = "var(--gold)";
            authOverallEl.style.textShadow = "0 0 15px rgba(251, 191, 36, 0.4)";
        }
    }

    const hopAnalysis = data.hops_analysis || {};
    const hriScore = Number(hopAnalysis.header_consistency_score ?? 0);
    animateValue("meta-hri", 0, hriScore, 1000, (v) => `${Math.round(v)}%`);
    
    // 3. FRONT-AND-CENTER AI NEURAL ENGINE SHOWCASE
    renderAIShowcase(ml);

    // 4. ELABORATED AUTHENTICATION PROTOCOL DEEP DIVE
    renderElaboratedAuth(auth);

    // 5. Evidence & Ledger Details
    setText("meta-hash", shorten(data.forensic_hash, 18));
    setText("meta-origin-ip", data.origin_ip || "Not available");
    setText("meta-total-hops", hopAnalysis.analyzed_hops?.length ?? 0);

    const originEvidence = data.origin_evidence || {};
    const geo = data.origin_geo || {};
    const geoLabel = geo.status === "RESOLVED" ? `${geo.city || "Unknown"}, ${geo.country || "Unknown"}` : "Lookup unavailable";
    setText("meta-origin-geo", geoLabel);
    setText("meta-origin-confidence", `${originEvidence.confidence || "NONE"} / ${geo.confidence || "NONE"}`);
    setText("meta-origin-source", originEvidence.source || "No source evidence");
    setText("meta-origin-isp", geo.status === "RESOLVED" ? `${geo.isp || "Unknown"} • ${geo.asn || "Unknown ASN"}` : "Unavailable");
    setText("origin-note", `${originEvidence.note || ""} ${geo.note || ""}`.trim());

    const ledger = data.ledger_receipt || {};
    setText("ledger-type", (ledger.ledger_type || "--").replaceAll("_", " "));
    setText("ledger-hash", shorten(ledger.record_hash, 18));

    // 6. Visual Sub-renderers
    try { plotFlightPath(hopAnalysis.analyzed_hops || []); } catch (e) { console.warn("Flight path render error:", e); }
    try { renderHopTable(hopAnalysis.analyzed_hops || []); } catch (e) { console.warn("Hop table render error:", e); }
    try { renderFactors(threat.explainability_factors || []); } catch (e) { console.warn("Factors render error:", e); }
    try { renderIOCGraph(data.ioc_graph || {}); } catch (e) { console.warn("IOC graph render error:", e); }

    window.setTimeout(() => mapInstance?.invalidateSize(), 150);

    // 7. Focus Transition to Geolocation Infrastructure Structure
    const geoCard = document.getElementById("geo-infrastructure-card");
    if (geoCard) {
        geoCard.classList.remove("highlight-pulse");
        void geoCard.offsetWidth;
        geoCard.classList.add("highlight-pulse");
    }

    if (lenis) {
        lenis.scrollTo("#geo-infrastructure-card", { offset: -30, duration: 1.3 });
    } else if (geoCard) {
        geoCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

/* ==========================================================================
   11. AI Neural Showcase Renderer
   ========================================================================== */
function renderAIShowcase(ml) {
    const prob = Number(ml.phishing_probability);
    const heroEl = document.getElementById("ai-prob-hero");
    const verdictEl = document.getElementById("ai-prob-verdict");
    const fillEl = document.getElementById("ai-confidence-fill");

    if (Number.isFinite(prob)) {
        animateValue("ai-prob-hero", 0, prob * 100, 1200, (v) => `${v.toFixed(1)}%`);
        if (fillEl) fillEl.style.width = `${Math.min(100, Math.max(0, prob * 100))}%`;

        if (prob >= 0.65) {
            if (verdictEl) {
                verdictEl.textContent = "PHISHING DETECTED";
                verdictEl.style.color = "#f43f5e";
                verdictEl.style.borderColor = "#f43f5e";
                verdictEl.style.backgroundColor = "rgba(244, 63, 94, 0.12)";
            }
        } else if (prob <= 0.35) {
            if (verdictEl) {
                verdictEl.textContent = "BENIGN / LEGITIMATE";
                verdictEl.style.color = "#34d399";
                verdictEl.style.borderColor = "#34d399";
                verdictEl.style.backgroundColor = "rgba(52, 211, 153, 0.12)";
            }
        } else {
            if (verdictEl) {
                verdictEl.textContent = "UNCERTAIN PATTERN";
                verdictEl.style.color = "#fbbf24";
                verdictEl.style.borderColor = "#fbbf24";
                verdictEl.style.backgroundColor = "rgba(251, 191, 36, 0.12)";
            }
        }
    } else {
        if (heroEl) heroEl.textContent = "--%";
        if (verdictEl) verdictEl.textContent = "UNCERTAIN";
        if (fillEl) fillEl.style.width = "0%";
    }

    // Extracted Semantic Tokens Display
    const tokensContainer = document.getElementById("ai-tokens-container");
    const tokenCountEl = document.getElementById("ai-token-count");
    if (!tokensContainer) return;

    tokensContainer.replaceChildren();
    const tokens = ml.matched_indicators || [];

    if (tokenCountEl) {
        tokenCountEl.textContent = `${tokens.length} indicator${tokens.length === 1 ? "" : "s"} extracted`;
    }

    if (!tokens.length) {
        const empty = document.createElement("div");
        if (Number.isFinite(prob) && prob <= 0.35) {
            empty.className = "ai-token-empty benign-state";
            empty.textContent = "✅ Benign lexical distribution. No coercive, financial, or credential-harvesting triggers detected.";
        } else {
            empty.className = "ai-token-empty";
            empty.textContent = "No high-weight deceptive lexical triggers were found in message body or subject.";
        }
        tokensContainer.appendChild(empty);
        return;
    }

    tokens.forEach((token, index) => {
        const chip = document.createElement("div");
        chip.className = "ai-token-chip";
        chip.style.animationDelay = `${index * 0.08}s`;

        const word = document.createElement("span");
        word.className = "ai-token-word";
        word.textContent = `"${token}"`;

        const badge = document.createElement("span");
        badge.className = "ai-token-badge";
        badge.textContent = "THREAT TRIGGER";

        chip.append(word, badge);
        tokensContainer.appendChild(chip);
    });
}

/* ==========================================================================
   12. Elaborated Authentication Protocol Deep Dive (SPF / DKIM / DMARC)
   ========================================================================== */
function renderElaboratedAuth(auth) {
    const spfStatus = auth.spf?.status || "NONE";
    const dkimStatus = auth.dkim?.status || "NONE";
    const dmarcStatus = auth.dmarc?.status || "NONE";

    renderAuthBadge("badge-spf", spfStatus);
    renderAuthBadge("badge-dkim", dkimStatus);
    renderAuthBadge("badge-dmarc", dmarcStatus);
    setText("auth-notice", auth.trust_notice || "Authentication provenance unavailable.");

    // Elaborated SPF Card
    const cardSpf = document.getElementById("card-spf");
    const impactSpf = document.getElementById("text-impact-spf");
    if (cardSpf) {
        cardSpf.className = "protocol-card";
        if (spfStatus === "PASS") {
            cardSpf.classList.add("status-pass");
            if (impactSpf) impactSpf.textContent = "SENDER AUTHORIZED: The transmitting server IP matches the published DNS SPF policy of the sender domain. Relay provenance confirmed.";
        } else if (spfStatus === "FAIL") {
            cardSpf.classList.add("status-fail");
            if (impactSpf) impactSpf.textContent = "SPOOFING ALERT (FAIL): Transmitting IP is NOT listed in the domain's SPF record. High probability of rogue server injection or forged MAIL FROM.";
        } else {
            cardSpf.classList.add("status-warn");
            if (impactSpf) impactSpf.textContent = "UNVERIFIED: Softfail, neutral, or unlisted DNS record. Origin server authority cannot be cryptographically proven.";
        }
    }

    // Elaborated DKIM Card
    const cardDkim = document.getElementById("card-dkim");
    const impactDkim = document.getElementById("text-impact-dkim");
    if (cardDkim) {
        cardDkim.className = "protocol-card";
        if (dkimStatus === "PASS") {
            cardDkim.classList.add("status-pass");
            if (impactDkim) impactDkim.textContent = "INTEGRITY VERIFIED: Cryptographic digital signature validated using sender's public DNS key. Message body and headers unmodified.";
        } else if (dkimStatus === "FAIL") {
            cardDkim.classList.add("status-fail");
            if (impactDkim) impactDkim.textContent = "TAMPERING DETECTED (FAIL): RSA/Ed25519 signature missing, revoked, or hash mismatch. Indicates in-transit manipulation or fraudulent sender.";
        } else {
            cardDkim.classList.add("status-warn");
            if (impactDkim) impactDkim.textContent = "ABSENT: No DKIM signature header present in this email evidence.";
        }
    }

    // Elaborated DMARC Card
    const cardDmarc = document.getElementById("card-dmarc");
    const impactDmarc = document.getElementById("text-impact-dmarc");
    if (cardDmarc) {
        cardDmarc.className = "protocol-card";
        if (dmarcStatus === "PASS") {
            cardDmarc.classList.add("status-pass");
            if (impactDmarc) impactDmarc.textContent = "STRICT ALIGNMENT CONFIRMED: Message passes SPF/DKIM alignment with the user-facing From: header. Executive impersonation averted.";
        } else if (dmarcStatus === "FAIL") {
            cardDmarc.classList.add("status-fail");
            if (impactDmarc) impactDmarc.textContent = "ALIGNMENT REJECTED (FAIL): Header From domain does not align with SPF or DKIM identities. Characteristic of BEC & executive spoofing.";
        } else {
            cardDmarc.classList.add("status-warn");
            if (impactDmarc) impactDmarc.textContent = "POLICY NONE / ABSENT: Domain does not enforce rejection policies. Susceptible to visual address spoofing.";
        }
    }
}

function shorten(value, length) {
    if (!value) return "--";
    return value.length > length ? `${value.slice(0, length)}…` : value;
}

function renderAuthBadge(elementId, status = "NONE") {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.className = "badge-tag";
    element.textContent = status;
    if (status === "PASS") element.classList.add("badge-pass");
    else if (status === "FAIL") element.classList.add("badge-fail");
    else if (status === "WARN") element.classList.add("badge-warn");
    else element.classList.add("badge-neutral");
}

/* ==========================================================================
   13. Leaflet Flight Path Plotter
   ========================================================================== */
function plotFlightPath(hops) {
    if (!mapInstance) return;
    hopMarkers.forEach((marker) => mapInstance.removeLayer(marker));
    hopMarkers = [];
    if (routePolyline) mapInstance.removeLayer(routePolyline);
    routePolyline = null;

    const points = [];
    (hops || []).forEach((hop, index) => {
        const latitude = Number(hop.geo?.latitude);
        const longitude = Number(hop.geo?.longitude);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || hop.geo?.is_private) return;
        const point = [latitude, longitude];
        points.push(point);
        const marker = L.circleMarker(point, {
            radius: index === 0 ? 9 : 6,
            fillColor: hop.anomaly ? "#fbbf24" : index === 0 ? "#f43f5e" : "#00f0ff",
            color: "#ffffff",
            weight: 2,
            fillOpacity: 0.95,
        }).addTo(mapInstance);
        const popup = document.createElement("div");
        popup.className = "map-popup";
        popup.textContent = `Hop ${hop.hop_number}: ${hop.ip || "internal"} • ${hop.geo.city || "Unknown"}, ${hop.geo.country || "Unknown"} • ${hop.from_mta || "Unknown"} → ${hop.by_mta || "Unknown"}`;
        marker.bindPopup(popup);
        hopMarkers.push(marker);
    });

    if (points.length > 1) {
        routePolyline = L.polyline(points, { color: "#00f0ff", weight: 3, opacity: 0.85, dashArray: "6,8" }).addTo(mapInstance);
        mapInstance.fitBounds(routePolyline.getBounds(), { padding: [40, 40] });
    } else if (points.length === 1) {
        mapInstance.setView(points[0], 5);
    } else {
        mapInstance.setView([20.5937, 78.9629], 3);
    }
}

function renderHopTable(hops) {
    const body = document.getElementById("hop-table-body");
    body.replaceChildren();
    if (!hops || !hops.length) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.textContent = "No Received headers were available for relay review.";
        return;
    }
    hops.forEach((hop) => {
        const row = body.insertRow();
        const deltaStr = hop.delta_seconds == null || isNaN(Number(hop.delta_seconds)) 
            ? "Origin/unknown" 
            : `${Number(hop.delta_seconds).toFixed(1)}s`;
        const values = [
            `#${hop.hop_number}`,
            hop.ip || "Internal",
            hop.geo?.status === "RESOLVED" ? `${hop.geo.city || "Unknown"}, ${hop.geo.country_code || "--"}` : "Unavailable",
            `${hop.from_mta || "Unknown"} → ${hop.by_mta || "Unknown"}`,
            deltaStr,
        ];
        values.forEach((value) => {
            const cell = row.insertCell();
            cell.textContent = value;
        });
        const statusCell = row.insertCell();
        const badge = document.createElement("span");
        badge.className = `badge-tag ${hop.anomaly ? "badge-warn" : "badge-neutral"}`;
        badge.textContent = hop.anomaly ? "TIMESTAMP ANOMALY" : "OBSERVED";
        statusCell.appendChild(badge);
    });
}

function renderFactors(factors) {
    const container = document.getElementById("factors-container");
    container.replaceChildren();
    if (!factors || !factors.length) {
        const message = document.createElement("p");
        message.className = "empty-state";
        message.textContent = "No weighted risk indicators were identified. This is not a guarantee that the message is safe.";
        container.appendChild(message);
        return;
    }
    factors.forEach((factor) => {
        const item = document.createElement("div");
        item.className = "factor-item";
        const heading = document.createElement("div");
        const category = document.createElement("strong");
        category.textContent = factor.category || "INDICATOR";
        const impact = document.createElement("span");
        impact.textContent = factor.impact || "";
        heading.append(category, impact);
        const detail = document.createElement("p");
        detail.textContent = factor.detail || "No detail available";
        item.append(heading, detail);
        container.appendChild(item);
    });
}

function renderIOCGraph(graph) {
    const container = document.getElementById("ioc-graph");
    container.replaceChildren();
    const nodes = graph?.nodes || [];
    if (!nodes.length) {
        container.textContent = "No indicators were extracted.";
        return;
    }
    nodes.forEach((node) => {
        const chip = document.createElement("div");
        chip.className = `ioc-node type-${String(node.type || "unknown").toLowerCase()}`;
        const type = document.createElement("span");
        type.textContent = node.type || "IOC";
        const label = document.createElement("strong");
        label.textContent = node.label || node.id;
        chip.append(type, label);
        container.appendChild(chip);
    });
}

async function exportPDF() {
    if (!currentReportData?.analysis_id) {
        showError("Run an analysis before exporting a report.");
        return;
    }
    const button = document.getElementById("btn-export-pdf");
    button.disabled = true;
    const originalHTML = button.innerHTML;
    button.innerHTML = "<span>Generating report…</span>";
    try {
        const response = await fetch("/api/export-pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ analysis_id: currentReportData.analysis_id }),
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.detail || "PDF generation failed");
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        const shortHash = (currentReportData.forensic_hash || "EVIDENCE").slice(0, 8).toUpperCase();
        link.download = `TRACE-MAIL-REPORT-${shortHash}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        showError(error.message);
    } finally {
        button.disabled = false;
        button.innerHTML = originalHTML;
    }
}
