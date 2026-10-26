/**
 * LinkProof Interactive Client Script.
 */

// Theme Management
(function initTheme() {
  const savedTheme = localStorage.getItem("linkproof_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const target = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", target);
  localStorage.setItem("linkproof_theme", target);
}

// Toast Notification
function showToast(message, duration = 2500) {
  let toast = document.getElementById("linkproof-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "linkproof-toast";
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.innerText = message;
  toast.style.display = "block";
  setTimeout(() => {
    toast.style.display = "none";
  }, duration);
}

// Copy to Clipboard
function copyToClipboard(text, successMsg = "Copied to clipboard!") {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMsg);
    }).catch(() => {
      fallbackCopy(text, successMsg);
    });
  } else {
    fallbackCopy(text, successMsg);
  }
}

function fallbackCopy(text, successMsg) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand("copy");
    showToast(successMsg);
  } catch (err) {
    showToast("Failed to copy text.");
  }
  document.body.removeChild(textarea);
}

// Tab Switching
function switchTab(evt, tabId) {
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(btn => btn.classList.remove("active"));

  const tabPanes = document.querySelectorAll(".tab-pane");
  tabPanes.forEach(pane => pane.classList.remove("active"));

  evt.currentTarget.classList.add("active");
  const targetPane = document.getElementById(tabId);
  if (targetPane) {
    targetPane.classList.add("active");
  }

  // Update hidden input_mode form field if present
  const inputModeField = document.getElementById("input_mode_field");
  if (inputModeField) {
    inputModeField.value = tabId.replace("tab-", "");
  }
}

// File Drag & Drop and Preview
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("qr-dropzone");
  const fileInput = document.getElementById("qr-file-input");
  const previewImg = document.getElementById("qr-preview-img");

  if (dropzone && fileInput) {
    ["dragenter", "dragover"].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      }, false);
    });

    dropzone.addEventListener("drop", (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        fileInput.files = files;
        handleFileSelect(files[0]);
      }
    });

    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
      }
    });
  }

  function handleFileSelect(file) {
    if (!file || !file.type.startsWith("image/")) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      if (previewImg) {
        previewImg.src = e.target.result;
        previewImg.style.display = "block";
      }
    };
    reader.readAsDataURL(file);
  }
});
