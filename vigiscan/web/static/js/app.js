(() => {
  document.documentElement.dataset.ready = "true";

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
})();
