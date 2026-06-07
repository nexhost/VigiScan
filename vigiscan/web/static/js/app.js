(() => {
  document.documentElement.dataset.ready = "true";

  const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
  const collapsed = window.localStorage?.getItem("vigiscan-sidebar-collapsed") === "true";
  if (collapsed) {
    document.body.classList.add("sidebar-collapsed");
  }
  sidebarToggle?.addEventListener("click", () => {
    document.body.classList.toggle("sidebar-collapsed");
    window.localStorage?.setItem(
      "vigiscan-sidebar-collapsed",
      String(document.body.classList.contains("sidebar-collapsed")),
    );
  });

  const field = document.querySelector(".particle-field");
  if (field) {
    const count = Number(field.dataset.particles || 24);
    for (let index = 0; index < count; index += 1) {
      const particle = document.createElement("span");
      particle.className = "particle";
      particle.style.left = `${Math.random() * 100}%`;
      particle.style.top = `${Math.random() * 100}%`;
      particle.style.setProperty("--duration", `${8 + Math.random() * 10}s`);
      particle.style.setProperty("--shift-x", `${-40 + Math.random() * 80}px`);
      particle.style.setProperty("--shift-y", `${-60 + Math.random() * 40}px`);
      particle.style.animationDelay = `${Math.random() * 6}s`;
      field.appendChild(particle);
    }
  }

  const loader = document.getElementById("scanLoader");
  document.querySelectorAll(".scan-launch-form").forEach((form) => {
    form.addEventListener("submit", () => {
      if (typeof form.checkValidity === "function" && !form.checkValidity()) {
        return;
      }
      if (!loader) {
        return;
      }
      loader.classList.add("active");
      loader.setAttribute("aria-hidden", "false");
    });
  });

  document.querySelectorAll(".metric-card, .glass-panel").forEach((card) => {
    card.addEventListener("pointermove", (event) => {
      const rect = card.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width) * 100;
      const y = ((event.clientY - rect.top) / rect.height) * 100;
      card.style.setProperty("--mouse-x", `${x}%`);
      card.style.setProperty("--mouse-y", `${y}%`);
    });
  });

  document.querySelectorAll(".pdf-download-btn").forEach((button) => {
    button.addEventListener("click", () => {
      button.classList.add("disabled");
      button.setAttribute("aria-disabled", "true");
      button.textContent = button.dataset.loadingText || "Generando...";
    });
  });

  document.querySelectorAll("[data-threat-map-frame]").forEach((frame) => {
    const shell = frame.closest(".threat-map-embed-shell");
    let loaded = false;
    frame.addEventListener("load", () => {
      loaded = true;
      shell?.classList.remove("is-blocked");
    });
    window.setTimeout(() => {
      if (!loaded) {
        shell?.classList.add("is-blocked");
      }
    }, 5000);
  });

  const threatStatNodes = document.querySelectorAll("[data-threat-stat]");
  if (threatStatNodes.length) {
    const updateThreatStats = async () => {
      try {
        const response = await fetch("/api/threat-stats", {
          headers: { Accept: "application/json" },
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        threatStatNodes.forEach((node) => {
          const key = node.dataset.threatStat;
          if (key && Object.hasOwn(data, key)) {
            node.textContent = data[key];
          }
        });
      } catch {
        // Keep the server-rendered values if the live update is unavailable.
      }
    };
    window.setInterval(updateThreatStats, 30000);
  }

  document.querySelectorAll("[data-count]").forEach((node) => {
    const target = Number(node.dataset.count);
    if (!Number.isFinite(target)) {
      return;
    }
    const decimals = String(node.dataset.count).includes(".") ? 1 : 0;
    const duration = 720;
    const startedAt = performance.now();
    const tick = (now) => {
      const progress = Math.min((now - startedAt) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = (target * eased).toFixed(decimals);
      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        node.textContent = target.toFixed(decimals);
      }
    };
    requestAnimationFrame(tick);
  });

  document.querySelectorAll("[title]").forEach((node) => {
    node.setAttribute("data-bs-toggle", node.getAttribute("data-bs-toggle") || "tooltip");
  });

  if (window.bootstrap?.Tooltip) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((node) => {
      window.bootstrap.Tooltip.getOrCreateInstance(node);
    });
  }

  window.requestAnimationFrame(() => {
    document.querySelectorAll(".skeleton-loading").forEach((node) => {
      node.classList.remove("skeleton-loading");
    });
  });
})();
