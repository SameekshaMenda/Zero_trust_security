const loginForm = document.getElementById("loginForm");
const scanForm = document.getElementById("scanForm");

if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const otp = document.getElementById("otp").value;

    const res = await fetch("http://localhost:5000/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, otp })
    });

    if (res.ok) {
      const data = await res.json();
      localStorage.setItem("token", data.token);
      window.location.href = "dashboard.html";
    } else {
      document.getElementById("errorMsg").classList.remove("hidden");
    }
  });
}

if (scanForm) {
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = localStorage.getItem("token");
    const url = document.getElementById("url").value;

    const res = await fetch("http://localhost:5000/scanner/scan", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const result = await res.json();
    const output = document.getElementById("scanResult");
    output.classList.remove("hidden");
    output.textContent = JSON.stringify(result, null, 2);
  });
}
