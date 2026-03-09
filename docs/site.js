"use strict";

(function () {
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (!conn) return;

  const saveDataEnabled = conn.saveData === true;
  const networkType = String(conn.effectiveType || "").toLowerCase();
  const slowNetwork = networkType.includes("2g");

  if (saveDataEnabled || slowNetwork) {
    document.body.classList.add("no-bg-video");
  }
})();

(function () {
  const thumbs = Array.from(document.querySelectorAll(".lightbox-thumb"));
  const lightbox = document.getElementById("lightbox");
  const image = document.getElementById("lightbox-image");
  const caption = document.getElementById("lightbox-caption");
  const btnClose = document.querySelector(".lightbox-close");
  const btnPrev = document.querySelector(".lightbox-prev");
  const btnNext = document.querySelector(".lightbox-next");

  if (!thumbs.length || !lightbox || !image || !caption || !btnClose || !btnPrev || !btnNext) return;

  let index = 0;

  function render() {
    const item = thumbs[index];
    const src = item.getAttribute("data-full") || item.getAttribute("src") || "";
    const text = item.getAttribute("data-caption") || item.getAttribute("alt") || "";
    image.setAttribute("src", src);
    image.setAttribute("alt", text);
    caption.textContent = text;
  }

  function openAt(i) {
    index = (i + thumbs.length) % thumbs.length;
    render();
    lightbox.classList.add("open");
    lightbox.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
  }

  function close() {
    lightbox.classList.remove("open");
    lightbox.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }

  function prev() {
    openAt(index - 1);
  }

  function next() {
    openAt(index + 1);
  }

  thumbs.forEach((thumb, i) => {
    thumb.addEventListener("click", () => openAt(i));
    thumb.setAttribute("tabindex", "0");
    thumb.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openAt(i);
      }
    });
  });

  btnClose.addEventListener("click", close);
  btnPrev.addEventListener("click", prev);
  btnNext.addEventListener("click", next);

  lightbox.addEventListener("click", (e) => {
    if (e.target === lightbox) close();
  });

  document.addEventListener("keydown", (e) => {
    if (!lightbox.classList.contains("open")) return;
    if (e.key === "Escape") close();
    else if (e.key === "ArrowLeft") prev();
    else if (e.key === "ArrowRight") next();
  });
})();
