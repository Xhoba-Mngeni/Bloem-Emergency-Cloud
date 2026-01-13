// --- CONFIG ---
const API_BASE = ""; // Relative path

// --- STATE ---
let currentUser = null;
let currentToken = localStorage.getItem('bec_token');

// --- AUTH ---
async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const mfaCode = document.getElementById('mfa-code').value;
    const errorMsg = document.getElementById('login-error');
    const btn = document.querySelector('#login-screen button');

    if (!username || !password) {
        errorMsg.textContent = "Please enter username and password";
        errorMsg.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = "Authenticating...";

    try {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        if (mfaCode) formData.append('mfa_code', mfaCode);

        const response = await fetch(`${API_BASE}/token`, {
            method: 'POST',
            body: formData
        });

        if (response.status === 403) {
            const err = await response.json();
            if (err.detail === "MFA_REQUIRED" || err.detail === "Invalid MFA Code") {
                document.getElementById('mfa-section').classList.remove('hidden');
                errorMsg.textContent = err.detail === "Invalid MFA Code" ? "Invalid Code. Try again." : "Two-Factor Auth Required";
                errorMsg.classList.remove('hidden');
                btn.textContent = "VERIFY 2FA";
                btn.disabled = false;
                return;
            }
        }

        if (!response.ok) throw new Error('Invalid credentials');

        const data = await response.json();
        currentToken = data.access_token;
        localStorage.setItem('bec_token', currentToken);
        if (data.refresh_token) {
            localStorage.setItem('bec_refresh', data.refresh_token);
        }
        
        // Decode token to get role (simple implementation)
        // In production, verify signature. Here just read payload.
        const payload = JSON.parse(atob(currentToken.split('.')[1]));
        currentUser = { username: payload.sub, role: payload.role, mfa_enabled: data.mfa_enabled };
        
        showSection('home');
        updateDashboardHeader();
        loadStats();
    } catch (err) {
        console.error(err);
        errorMsg.classList.remove('hidden');
        errorMsg.textContent = "Login Failed: Check credentials";
    } finally {
        if (btn.textContent !== "VERIFY 2FA") {
            btn.disabled = false;
            btn.textContent = "SECURE LOGIN";
        }
    }
}

function logout() {
    currentToken = null;
    currentUser = null;
    localStorage.removeItem('bec_token');
    location.reload();
}

function updateDashboardHeader() {
    const profile = document.querySelector('.user-profile');
    if (currentUser) {
        profile.innerHTML = `<strong>${currentUser.username}</strong> <span class="badge">${currentUser.role || 'MD'}</span>`;
        
        // RBAC: Hide/Show Admin Tabs
        const isAdmin = currentUser.role === 'admin';
        const canAdmit = currentUser.role === 'admin' || currentUser.role === 'doctor';
        
        // 1. Audit Logs Tab
        const logsBtn = document.getElementById('btn-logs');
        if (logsBtn) logsBtn.style.display = isAdmin ? 'block' : 'none';

        // 2. Security Events Stat Card (2nd child of stats-grid)
        const securityStat = document.querySelector('.stats-grid .stat-card:nth-child(2)');
        if (securityStat) securityStat.style.display = isAdmin ? 'block' : 'none';

        const unlockBtn = document.getElementById('btn-unlock');
        if (unlockBtn) unlockBtn.style.display = isAdmin ? 'inline-block' : 'none';

        const admitBtn = document.getElementById('btn-admit');
        if (admitBtn) admitBtn.style.display = canAdmit ? 'inline-block' : 'none';
    }
}

// --- UI HELPERS ---
function toggleContrast() {
    document.body.classList.toggle('high-contrast');
}

function showReviewModal() {
    // Get values
    const id = document.getElementById('new-id').value;
    const fname = document.getElementById('new-fname').value;
    const lname = document.getElementById('new-lname').value;
    const ecNumber = document.getElementById('new-contact').value;
    const ecName = document.getElementById('new-ec-name').value;
    const ecSurname = document.getElementById('new-ec-surname').value;
    const ecRelation = document.getElementById('new-ec-relation').value;
    const blood = document.getElementById('new-blood').value;
    const allergies = document.getElementById('new-allergies').value;
    const surgeries = document.getElementById('new-surgeries').value;
    const diagnosis = document.getElementById('new-condition').value;
    const medication = document.getElementById('new-med').value;
    
    if (!id || !fname || !lname) {
        alert("Please fill in ID, First Name, and Last Name.");
        return;
    }

    // Populate modal
    document.getElementById('review-id').textContent = id;
    document.getElementById('review-name').textContent = `${fname} ${lname}`;
    document.getElementById('review-ec-number').textContent = ecNumber || '—';
    document.getElementById('review-ec-name').textContent = `${ecName || ''} ${ecSurname || ''}`.trim() || '—';
    document.getElementById('review-ec-relation').textContent = ecRelation || '—';
    document.getElementById('review-blood').textContent = blood || '—';
    document.getElementById('review-allergies').textContent = allergies || '—';
    document.getElementById('review-surgeries').textContent = surgeries || '—';
    document.getElementById('review-diagnosis').textContent = diagnosis || '—';
    document.getElementById('review-med').textContent = medication || '—';
    
    // Show modal
    document.getElementById('confirm-modal').classList.remove('hidden');
}

function closeReviewModal() {
    document.getElementById('confirm-modal').classList.add('hidden');
}

async function submitFinalPatient() {
    const payload = {
        sa_id: document.getElementById('new-id').value,
        first_name: document.getElementById('new-fname').value,
        last_name: document.getElementById('new-lname').value,
        blood_type: document.getElementById('new-blood').value || null,
        allergies: document.getElementById('new-allergies').value || "None Known",
        emergency_contact: document.getElementById('new-contact').value || "Unknown",
        emergency_contact_name: document.getElementById('new-ec-name').value || null,
        emergency_contact_surname: document.getElementById('new-ec-surname').value || null,
        emergency_contact_relationship: document.getElementById('new-ec-relation').value || null,
        previous_surgeries: document.getElementById('new-surgeries').value || "None",
        consent_status: "GRANTED",
        condition: document.getElementById('new-condition').value || null,
        medication: document.getElementById('new-med').value || null
    };

    const btn = document.querySelector('#confirm-modal .btn-primary');
    btn.disabled = true;
    btn.textContent = "Processing...";

    try {
        const res = await apiFetch(`${API_BASE}/patient/add`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            alert("Patient Admitted Successfully ✅");
            closeReviewModal();
            // Clear form
            document.querySelectorAll('#section-admit input').forEach(i => i.value = '');
            showSection('search');
        } else {
            let message = "Submission Failed";
            try {
                const err = await res.json();
                if (err && err.detail) {
                    if (Array.isArray(err.detail)) {
                        message = err.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
                    } else if (typeof err.detail === 'string') {
                        message = err.detail;
                    } else {
                        message = JSON.stringify(err.detail);
                    }
                }
            } catch (_) {}
            alert("Error: " + message);
        }
    } catch (e) {
        alert("Network Error during submission");
    } finally {
        btn.disabled = false;
        btn.textContent = "CONFIRM";
    }
}

async function apiFetch(url, options = {}) {
    const init = { ...options };
    init.headers = init.headers || {};
    if (currentToken) {
        init.headers['Authorization'] = `Bearer ${currentToken}`;
    }
    let res = await fetch(url, init);
    if (res.status === 401) {
        try {
            const err = await res.clone().json().catch(() => null);
            if (err && err.detail === "Could not validate credentials") {
                const rt = localStorage.getItem('bec_refresh');
                if (rt) {
                    const fd = new FormData();
                    fd.append('refresh_token', rt);
                    const r2 = await fetch(`${API_BASE}/auth/refresh`, { method: 'POST', body: fd });
                    if (r2.ok) {
                        const tok = await r2.json();
                        currentToken = tok.access_token;
                        localStorage.setItem('bec_token', currentToken);
                        localStorage.setItem('bec_refresh', tok.refresh_token);
                        init.headers['Authorization'] = `Bearer ${currentToken}`;
                        res = await fetch(url, init);
                    } else {
                        throw new Error('Refresh failed');
                    }
                }
            }
        } catch (_) {
            // fall through
        }
    }
    return res;
}

// --- NAVIGATION ---
function showSection(sectionId) {
    // Hide all sections
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    
    ['home', 'search', 'admit'].forEach(id => {
        const el = document.getElementById(`section-${id}`);
        if (el) el.classList.add('hidden');
        const btn = document.getElementById(`btn-${id}`);
        if (btn) btn.classList.remove('active');
    });

    if (sectionId === 'admit' && currentUser && !(currentUser.role === 'admin' || currentUser.role === 'doctor')) {
        sectionId = 'search';
        alert("Only admins and doctors can admit patients.");
    }

    // Show target
    const target = document.getElementById(`section-${sectionId}`);
    if (target) target.classList.remove('hidden');
    
    const navBtn = document.getElementById(`btn-${sectionId}`);
    if (navBtn) navBtn.classList.add('active');
}

// --- MFA ---
async function startMfaSetup() {
    try {
        const res = await fetch(`${API_BASE}/auth/mfa/setup`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        
        if (res.ok) {
            const data = await res.json();
            document.getElementById('mfa-qr').src = data.qr_code;
            document.getElementById('mfa-secret-temp').value = data.secret;
            document.getElementById('mfa-modal').classList.remove('hidden');
        } else {
            alert("Setup Failed");
        }
    } catch (e) {
        console.error(e);
        alert("Network Error");
    }
}

async function confirmMfa() {
    const code = document.getElementById('mfa-verify-code').value;
    const secret = document.getElementById('mfa-secret-temp').value;
    
    try {
        const formData = new FormData();
        formData.append('code', code);
        formData.append('secret', secret);
        
        const res = await fetch(`${API_BASE}/auth/mfa/verify`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });
        
        if (res.ok) {
            alert("MFA Enabled! You will need this code next time you login.");
            closeMfaModal();
        } else {
            alert("Invalid Code. Please try again.");
        }
    } catch (e) {
        alert("Verification Error");
    }
}

function closeMfaModal() {
    document.getElementById('mfa-modal').classList.add('hidden');
    document.getElementById('mfa-verify-code').value = '';
}

// --- API CALLS ---
async function loadStats() {
    try {
        const res = await fetch(`${API_BASE}/admin/stats`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById('stat-patients').textContent = data.total_patients;
            document.getElementById('stat-activity').textContent = data.todays_activity;
            document.getElementById('stat-status').textContent = data.system_status;
        }
    } catch (e) {
        console.error("Stats load error", e);
    }
}

async function attemptStandardSearch() {
    const saId = document.getElementById('sa-id-input').value;
    if (!saId) return alert("Please enter an SA ID");

    showLoading(true);
    document.getElementById('patient-results').classList.add('hidden');
    document.getElementById('break-glass-modal').classList.add('hidden');

    try {
        const res = await fetch(`${API_BASE}/patient/search?sa_id=${saId}`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        if (res.status === 200) {
            const data = await res.json();
            renderPatient(data);
        } else if (res.status === 403 || res.status === 401) {
             // If access denied (restricted), show break glass
             // Note: Current backend might return 404 if not found, or just return data.
             // If we implement Restricted access properly, it would be 403.
             // For now, if 404, just say not found.
             if (res.status === 404) {
                 alert("Patient not found.");
             } else {
                 // Assume Restricted
                 document.getElementById('break-glass-modal').classList.remove('hidden');
             }
        } else {
            alert("Search failed: " + res.statusText);
        }
    } catch (e) {
        alert("Network Error");
    } finally {
        showLoading(false);
    }
}

async function executeBreakGlass() {
    const saId = document.getElementById('sa-id-input').value;
    const reason = document.getElementById('access-reason').value;
    
    if (!reason) return alert("You must provide a reason for emergency access.");

    showLoading(true);
    try {
        const res = await fetch(`${API_BASE}/emergency-summary`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sa_id: saId, reason: reason })
        });

        if (res.ok) {
            const data = await res.json();
            document.getElementById('break-glass-modal').classList.add('hidden');
            renderPatient(data);
        } else {
            alert("Break Glass Failed: " + res.statusText);
        }
    } catch (e) {
        alert("Critical Error");
    } finally {
        showLoading(false);
    }
}

async function loadAuditLogs() {
    try {
        const res = await fetch(`${API_BASE}/admin/logs`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        if (res.ok) {
            const logs = await res.json();
            // Simple alert for now or modal
            let logText = logs.map(l => `${l.time} - ${l.doctor} viewed ${l.patient_sa_id} (${l.reason})`).join('\n');
            alert("Recent Logs:\n" + logText);
        } else {
            alert("Access Denied (Admin Only)");
        }
    } catch (e) {
        console.error(e);
    }
}

// --- RENDER ---
function renderPatient(data) {
    const p = data.patient;
    const analysis = data.ai_safety_analysis;

    document.getElementById('p-name').textContent = `${p.first_name} ${p.last_name}`;
    document.getElementById('p-id').textContent = p.sa_id;
    document.getElementById('p-blood').textContent = p.blood_type;
    const ecName = [p.emergency_contact_name, p.emergency_contact_surname].filter(Boolean).join(' ');
    const ecRel = p.emergency_contact_relationship ? ` (${p.emergency_contact_relationship})` : '';
    const ecNum = p.emergency_contact || '';
    document.getElementById('p-contact').textContent = [ecName + ecRel, ecNum].filter(Boolean).join(': ');
    document.getElementById('p-allergies').textContent = p.allergies;
    document.getElementById('p-surgeries').textContent = p.previous_surgeries;
    document.getElementById('p-consent').textContent = p.consent_status;

    // History
    const hList = document.getElementById('history-list');
    if (data.medical_history && data.medical_history.length > 0) {
        hList.innerHTML = data.medical_history.map(h => `<li><strong>${h.name}</strong> (${h.date})</li>`).join('');
    } else {
        hList.innerHTML = `<li>None / information not uploaded</li>`;
    }

    // Meds
    const mList = document.getElementById('med-list');
    if (data.current_medications && data.current_medications.length > 0) {
        mList.innerHTML = data.current_medications.map(m => `<li>${m.name} - ${m.dosage}</li>`).join('');
    } else {
        mList.innerHTML = `<li>None / information not uploaded</li>`;
    }

    // AI Warnings
    const aiDiv = document.getElementById('ai-warnings');
    aiDiv.innerHTML = '';
    
    if (analysis.warnings && analysis.warnings.length > 0) {
        const isHighRisk = analysis.risk_level === 'HIGH';
        const sevClass = isHighRisk ? 'severity-HIGH' : 'severity-SAFE';
        const sevTitle = isHighRisk ? 'CRITICAL SAFETY ALERT' : 'Potential Interactions';
        
        // Build list with Explainability (Reason + Source)
        const listHtml = analysis.warnings.map(w => `
            <li style="margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px dashed rgba(0,0,0,0.1);">
                <strong style="font-size: 1.05em;">${w.message}</strong><br>
                <small style="display: block; margin-top: 5px; color: inherit; opacity: 0.9;">
                    <strong>Why?</strong> ${w.reason}<br>
                    <strong>Source:</strong> ${w.source} | <strong>Confidence:</strong> ${w.confidence}%
                </small>
            </li>
        `).join('');

        aiDiv.innerHTML = `<div class="alert-box ${sevClass}" style="${!isHighRisk ? 'border-color: orange; color: #d84315;' : ''}">
             <h3 style="margin-top:0;">⚠️ ${sevTitle}</h3>
             <ul style="list-style: none; padding-left: 0; margin-bottom: 0;">${listHtml}</ul>
        </div>`;
    }

    document.getElementById('patient-results').classList.remove('hidden');
}

function showLoading(show) {
    const el = document.getElementById('loading-overlay');
    if (show) el.classList.remove('hidden');
    else el.classList.add('hidden');
}

// --- INIT ---
// Check if logged in
if (currentToken) {
    // Decode token to get user
    try {
        const payload = JSON.parse(atob(currentToken.split('.')[1]));
        currentUser = { username: payload.sub, role: payload.role };
        showSection('home');
        updateDashboardHeader();
        loadStats();
    } catch (e) {
        logout();
    }
}

async function adminUnlockUser() {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Admin only");
        return;
    }
    const target = prompt("Enter username to unlock");
    if (!target) return;
    try {
        const formData = new FormData();
        formData.append('target_username', target);
        const res = await fetch(`${API_BASE}/admin/unlock-user`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });
        if (res.ok) {
            alert("User unlocked");
        } else {
            const err = await res.json().catch(() => ({}));
            alert("Unlock failed: " + (err.detail || res.statusText));
        }
    } catch (e) {
        alert("Network error");
    }
}
