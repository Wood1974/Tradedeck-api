// ============================================================
// TRADEDECK SHIELD — shield.js (MERGED COMPLETE VERSION)
// Combines: real Stripe Elements payment, trade-aware job brief,
// local point generation, close-out system, AI photo analysis
// ============================================================
//
// INTEGRATION POINTS IN YOUR EXISTING APP:
//   1. Post a Job form      → renderShieldBrief(container, onReady)
//   2. Pay button           → purchaseShieldPerJob(jobId, amount, description)
//   3. Homeowner nav tab    → renderShieldDashboard(container)
//   4. Contractor job view  → renderContractorUploadFlow(container, shieldJobId, pointId)
//   5. Contractor profile   → subscribeContractorToShield(container)
//   6. Contractor job card  → renderShieldBadge(contractorId, container)
//   7. Job close-out        → renderShieldCloseOut(container, shieldJobId)
//
// Requires: Supabase client (sb) available globally
// Stripe.js is lazy-loaded only when payment is about to happen

const STRIPE_PK        = 'pk_test_51TLWkTDNZcAJj6Kyd84RVIQ0qPO1iHP109ccBL4P9OQvShE21T291c4BhhtC8Z6CEYQKqmtjj2b6UZQe1n1CusGC00KNY7CwAl'
const API_BASE         = 'https://tradedeck-api.onrender.com'
const CONTRACTOR_SUB_PRICE = 49

// ─────────────────────────────────────────────────
// SHIELD PRICING
// ─────────────────────────────────────────────────
const SHIELD_TIERS = [
  { label: 'Under $15,000',     max: 15000,    price: 79  },
  { label: '$15,000–$50,000',   max: 50000,    price: 129 },
  { label: 'Over $50,000',      max: Infinity, price: 199 },
]

function getShieldPrice(budget) {
  return (SHIELD_TIERS.find(t => budget <= t.max) || SHIELD_TIERS[2]).price
}

// ─────────────────────────────────────────────────
// LAZY STRIPE LOADER
// ─────────────────────────────────────────────────
function loadStripeScript() {
  return new Promise((resolve, reject) => {
    if (document.getElementById('stripe-js')) { resolve(); return }
    const s  = document.createElement('script')
    s.id     = 'stripe-js'
    s.src    = 'https://js.stripe.com/v3/'
    s.onload  = resolve
    s.onerror = () => reject(new Error('Failed to load Stripe.js'))
    document.head.appendChild(s)
  })
}

// ============================================================
// PART 1 — JOB BRIEF ENGINE
// Trade detection, description scoring, local point generation
// ============================================================

const TRADE_PROFILES = {
  roofing: {
    keywords: ['roof','roofing','shingle','flashing','gutter','fascia','soffit','ridge','underlayment','decking'],
    questions: ['What is the total square footage of the roof?','What roofing material — asphalt shingle, metal, tile, or flat?','Is the existing deck being replaced or just the surface?','Any skylights, chimneys, or penetrations that need flashing?'],
    points: [
      { label: 'Deck Inspection',       description: 'Photo of the exposed roof deck showing condition of sheathing before any new material goes down.' },
      { label: 'Underlayment Complete', description: 'Photo showing full coverage of felt or synthetic underlayment across all roof planes.' },
      { label: 'Flashing Installed',    description: 'Photo of all flashing at valleys, penetrations, and wall transitions before shingles cover them.' },
      { label: 'Shingles at Midpoint',  description: 'Photo showing shingle installation progress at the halfway point with visible nailing pattern.' },
      { label: 'Final Surface + Ridge', description: 'Photo of completed roof surface including ridge cap, all penetrations sealed, and gutters reattached.' },
    ],
  },
  kitchen: {
    keywords: ['kitchen','cabinet','countertop','backsplash','sink','appliance','island','pantry','remodel','renovation'],
    questions: ['Are you moving or adding plumbing or electrical?','Are the cabinets being replaced or refaced?','What countertop material — quartz, granite, laminate, butcher block?','Is the flooring being replaced as part of this project?'],
    points: [
      { label: 'Demo Complete',          description: 'Photo of stripped kitchen showing all removed cabinets, flooring, and wall surfaces before new work begins.' },
      { label: 'Rough-In Inspected',     description: 'Photo of all rough plumbing and electrical in walls before drywall or cabinets cover them.' },
      { label: 'Cabinets Installed',     description: 'Photo of all upper and lower cabinets hung, level, and secured — before countertops arrive.' },
      { label: 'Countertops + Plumbing', description: 'Photo of countertops set and sink/faucet connected with supply lines visible.' },
      { label: 'Final — Appliances In',  description: 'Photo of fully completed kitchen with appliances installed, backsplash done, and all trim in place.' },
    ],
  },
  bathroom: {
    keywords: ['bathroom','bath','shower','tub','tile','vanity','toilet','plumbing','fixture','grout'],
    questions: ['Is the shower or tub being replaced?','Are you moving any plumbing or adding a fixture?','What is the approximate square footage of the bathroom?','Is the flooring being replaced?'],
    points: [
      { label: 'Demo + Waterproofing',   description: 'Photo showing cement board or waterproof membrane on shower walls before any tile is set.' },
      { label: 'Rough Plumbing',         description: 'Photo of all rough plumbing — supply and drain — before walls close.' },
      { label: 'Tile at Midpoint',       description: 'Photo showing tile installation in progress with visible layout and grout lines.' },
      { label: 'Fixture Rough-In',       description: 'Photo of toilet, vanity, and shower fixture rough-ins before final trim pieces.' },
      { label: 'Final Complete',         description: 'Photo of completed bathroom with all fixtures installed, grout sealed, and accessories in place.' },
    ],
  },
  electrical: {
    keywords: ['electrical','wiring','panel','circuit','outlet','switch','breaker','lighting','generator','EV charger'],
    questions: ['Is this a panel upgrade, new circuits, or fixture replacements?','Is a permit required in your municipality?','How many circuits or outlets are being added?','Is this work being done in a finished or unfinished space?'],
    points: [
      { label: 'Panel / Service Photo',  description: 'Photo of the main panel before work begins showing existing breaker layout and service rating.' },
      { label: 'Wire Rough-In',          description: 'Photo of all new wire runs in walls or ceiling before drywall covers them.' },
      { label: 'Connections at Box',     description: 'Photo of wire terminations inside junction and device boxes before cover plates.' },
      { label: 'Permit Inspection',      description: 'Photo of the permit inspection card or inspector sign-off document posted on site.' },
      { label: 'Final — Devices Live',   description: 'Photo of all outlets, switches, and fixtures installed and covers plates on.' },
    ],
  },
  plumbing: {
    keywords: ['plumbing','pipe','drain','water heater','sewer','leak','fixture','supply line','shutoff','pressure'],
    questions: ['Is this repair, replacement, or new installation?','Copper, PEX, or PVC?','Is a permit required?','Is the water heater being replaced as part of this?'],
    points: [
      { label: 'Existing Condition',    description: 'Photo of existing pipe condition, connections, and any visible damage before work begins.' },
      { label: 'Pipe Rough-In',         description: 'Photo of all new supply and drain lines before walls or floors close.' },
      { label: 'Pressure Test',         description: 'Photo of pressure gauge showing system holding pressure — or the gauge reading during test.' },
      { label: 'Connections Complete',  description: 'Photo of all finished connections at fixtures, shutoffs, and main tie-ins.' },
      { label: 'Final — Water On',      description: 'Photo confirmation all fixtures run, no visible leaks, and water heater operational if replaced.' },
    ],
  },
  hvac: {
    keywords: ['HVAC','furnace','AC','air conditioning','ductwork','heat pump','thermostat','ventilation','mini split','boiler'],
    questions: ['Full system replacement or repair?','What is the square footage being conditioned?','Forced air, mini-split, or radiant?','Is new ductwork required?'],
    points: [
      { label: 'Equipment Delivery',    description: 'Photo of new equipment — unit model and serial number visible — before installation begins.' },
      { label: 'Duct Rough-In',         description: 'Photo of ductwork installation before drywall or ceiling tiles cover it.' },
      { label: 'Equipment Set',         description: 'Photo of indoor and outdoor units fully mounted and connected — refrigerant lines visible.' },
      { label: 'Electrical + Controls', description: 'Photo of disconnect, thermostat wiring, and control connections before covers.' },
      { label: 'Performance Test',      description: 'Photo of system operating — thermostat set point and actual temperature reading visible.' },
    ],
  },
  concrete: {
    keywords: ['concrete','foundation','slab','driveway','patio','footing','pour','rebar','form','sidewalk'],
    questions: ['Is this a structural pour or decorative flatwork?','What is the square footage?','Is rebar or wire mesh being used?','Any drainage or slope requirements?'],
    points: [
      { label: 'Sub-Base Ready',        description: 'Photo of compacted sub-base, forms set, and any reinforcement in place before the pour.' },
      { label: 'Rebar / Mesh',          description: 'Photo of all rebar or wire mesh positioned and supported at correct height in forms.' },
      { label: 'Pour in Progress',       description: 'Photo during the pour showing concrete being placed and screeded.' },
      { label: 'Finish + Cure',         description: 'Photo of finished surface texture and curing compound or blanket applied.' },
      { label: 'Forms Stripped',        description: 'Photo of completed slab with forms removed showing edges and any control joints cut.' },
    ],
  },
  framing: {
    keywords: ['framing','addition','room','wall','joist','beam','header','stud','lumber','structure'],
    questions: ['Is this new construction, an addition, or interior remodel?','Any load-bearing walls being moved?','Is an engineer stamp required?','What is the approximate square footage?'],
    points: [
      { label: 'Foundation / Plate',    description: 'Photo of sill plate or bottom plate anchored to foundation or subfloor.' },
      { label: 'Wall Framing',          description: 'Photo of all exterior and interior walls framed, plumb, and braced.' },
      { label: 'Header + Beam',         description: 'Photo of all headers over openings and any structural beams installed.' },
      { label: 'Roof / Floor System',   description: 'Photo of roof rafters or floor joists complete with blocking and hangers.' },
      { label: 'Sheathing Complete',    description: 'Photo of exterior sheathing fully applied and nailed before wrap or siding.' },
    ],
  },
  flooring: {
    keywords: ['floor','flooring','hardwood','LVP','tile','carpet','laminate','subfloor','underlayment','install'],
    questions: ['What flooring material is being installed?','Is the subfloor being replaced or repaired?','What is the square footage?','Is this a floating floor or nail/glue down?'],
    points: [
      { label: 'Subfloor Inspection',   description: 'Photo of existing subfloor showing condition — any soft spots, squeaks, or height transitions marked.' },
      { label: 'Subfloor Prep',         description: 'Photo of subfloor after any repairs, leveling compound cured, and moisture barrier if required.' },
      { label: 'Layout Line',           description: 'Photo showing chalk lines and starting wall before first row of flooring is set.' },
      { label: 'Install at Midpoint',   description: 'Photo of flooring installation at approximately 50% complete showing pattern and seams.' },
      { label: 'Final + Trim',          description: 'Photo of completed floor with all transitions, thresholds, and base trim installed.' },
    ],
  },
  general: {
    keywords: [],
    questions: ['What is the primary trade involved — roofing, plumbing, electrical, HVAC, or other?','What is the approximate square footage or scope?','Is a permit required?','Are there any existing conditions we should know about?'],
    points: [
      { label: 'Site Condition',        description: 'Photo documenting existing site conditions before any work begins.' },
      { label: 'Demo / Prep Complete',  description: 'Photo showing demolition or prep work completed and area ready for new work.' },
      { label: 'Rough Work',            description: 'Photo of primary structural, mechanical, or rough work before it is covered.' },
      { label: 'At Midpoint',           description: 'Photo of project at approximately 50% completion.' },
      { label: 'Final Complete',        description: 'Photo of fully completed work ready for homeowner inspection.' },
    ],
  },
}

function detectTrade(description) {
  const text = description.toLowerCase()
  let bestTrade = 'general'
  let bestScore = 0
  for (const [trade, profile] of Object.entries(TRADE_PROFILES)) {
    if (trade === 'general') continue
    const score = profile.keywords.filter(k => text.includes(k)).length
    if (score > bestScore) { bestScore = score; bestTrade = trade }
  }
  return bestTrade
}

function scoreDescription(description) {
  const text = description.toLowerCase()
  let score = 0
  const feedback = []

  // Length
  const words = text.split(/\s+/).filter(Boolean).length
  if (words >= 30) score += 20
  else if (words >= 15) { score += 10; feedback.push('Add more detail about the work needed') }
  else { feedback.push('Description is too short — add what needs to be done and where') }

  // Measurements
  if (/\d+\s*(sq|square|sf|ft|foot|feet|inch|meter|m²|yard)/.test(text)) score += 20
  else feedback.push('Include square footage or dimensions')

  // Materials mentioned
  if (/\b(wood|tile|concrete|drywall|pex|copper|asphalt|vinyl|hardwood|metal|brick|stucco|lvp|granite|quartz)\b/.test(text)) score += 20
  else feedback.push('Mention the materials to be used')

  // Action verbs
  if (/\b(install|replace|repair|remove|build|add|upgrade|remodel|renovate|fix|seal|paint|demo|demolish)\b/.test(text)) score += 20
  else feedback.push('Describe the action — install, replace, repair, etc.')

  // Trade specifics
  const trade = detectTrade(description)
  if (trade !== 'general') score += 20

  return { score: Math.min(score, 100), feedback, trade }
}

function getLocalPoints(description) {
  const trade = detectTrade(description)
  return TRADE_PROFILES[trade].points
}

// ─────────────────────────────────────────────────
// SHIELD BRIEF UI
// Drop into Post a Job form — scores description live,
// asks follow-up questions, previews the 5 checkpoints
// onReady(description) is called when the description
// is good enough (score >= 70) and the user confirms
// ─────────────────────────────────────────────────
function renderShieldBrief(container, onReady) {
  const wrap = document.createElement('div')
  wrap.className = 'shield-brief-wrap'
  wrap.innerHTML = `
    <div class="shield-brief-header">
      <span class="shield-icon">🛡️</span>
      <div>
        <strong class="shield-brief-title">TradeDeck Shield</strong>
        <span class="shield-brief-sub">AI monitors 5 critical checkpoints on your job</span>
      </div>
    </div>
    <textarea
      id="shield-brief-input"
      class="shield-brief-textarea"
      placeholder="Describe your project in detail. The more specific you are, the more accurate your AI checkpoints will be."
      rows="4"
    ></textarea>
    <div id="shield-brief-score-bar-wrap" class="shield-score-bar-wrap" style="display:none">
      <div id="shield-brief-score-bar" class="shield-score-bar"></div>
    </div>
    <div id="shield-brief-feedback" class="shield-brief-feedback"></div>
    <div id="shield-brief-questions" class="shield-brief-questions"></div>
    <div id="shield-brief-points-preview" class="shield-brief-points-preview" style="display:none"></div>
    <button id="shield-brief-confirm" class="shield-pay-btn" style="display:none">
      Confirm — Generate My 5 Checkpoints
    </button>
  `

  container.appendChild(wrap)

  const textarea   = wrap.querySelector('#shield-brief-input')
  const scoreBar   = wrap.querySelector('#shield-brief-score-bar')
  const scoreWrap  = wrap.querySelector('#shield-brief-score-bar-wrap')
  const feedbackEl = wrap.querySelector('#shield-brief-feedback')
  const questionsEl = wrap.querySelector('#shield-brief-questions')
  const pointsEl   = wrap.querySelector('#shield-brief-points-preview')
  const confirmBtn = wrap.querySelector('#shield-brief-confirm')

  let debounceTimer = null

  textarea.addEventListener('input', () => {
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => updateBrief(textarea.value), 400)
  })

  function updateBrief(text) {
    if (text.trim().length < 10) {
      scoreWrap.style.display = 'none'
      feedbackEl.innerHTML = ''
      questionsEl.innerHTML = ''
      pointsEl.style.display = 'none'
      confirmBtn.style.display = 'none'
      return
    }

    const { score, feedback, trade } = scoreDescription(text)
    const points = TRADE_PROFILES[trade].points
    const questions = TRADE_PROFILES[trade].questions

    // Score bar
    scoreWrap.style.display = 'block'
    scoreBar.style.width = score + '%'
    scoreBar.style.background = score >= 70 ? '#2d7a4f' : score >= 40 ? '#d4a017' : '#c0392b'
    scoreBar.title = `Description quality: ${score}/100`

    // Feedback
    feedbackEl.innerHTML = feedback.length
      ? `<ul class="shield-feedback-list">${feedback.map(f => `<li>${f}</li>`).join('')}</ul>`
      : `<p class="shield-feedback-ok">✅ Great description — ${trade} project detected</p>`

    // Follow-up questions if score is low
    if (score < 70 && questions.length) {
      questionsEl.innerHTML = `
        <p class="shield-questions-label">Answer these to improve your checkpoints:</p>
        <ul class="shield-questions-list">
          ${questions.map(q => `<li>${q}</li>`).join('')}
        </ul>
      `
    } else {
      questionsEl.innerHTML = ''
    }

    // Points preview
    pointsEl.style.display = 'block'
    pointsEl.innerHTML = `
      <p class="shield-points-label">Your 5 AI checkpoints:</p>
      ${points.map((p, i) => `
        <div class="shield-point-preview">
          <span class="shield-point-num-sm">${i + 1}</span>
          <div>
            <strong>${p.label}</strong>
            <p>${p.description}</p>
          </div>
        </div>
      `).join('')}
    `

    // Confirm button
    if (score >= 50) {
      confirmBtn.style.display = 'block'
      confirmBtn.textContent = score >= 70
        ? 'Confirm — Generate My 5 Checkpoints'
        : 'Continue with current description'
    } else {
      confirmBtn.style.display = 'none'
    }
  }

  confirmBtn.addEventListener('click', () => {
    const description = textarea.value.trim()
    if (description && onReady) onReady(description)
  })

  // Return textarea reference so Post a Job form can read the value
  return {
    getValue: () => textarea.value.trim(),
    getPoints: () => getLocalPoints(textarea.value.trim()),
  }
}

// ============================================================
// PART 2 — PAYMENT FLOW
// ============================================================

// ─────────────────────────────────────────────────
// SHIELD TOGGLE (simpler alternative to the Brief UI)
// Use renderShieldBrief() above for the full experience.
// This is a lightweight toggle for minimal Post a Job forms.
// ─────────────────────────────────────────────────
function renderShieldToggle(container, jobId, jobBudget = 0, jobDescription = '') {
  const price   = getShieldPrice(jobBudget)
  const elected = { value: false }

  const box = document.createElement('div')
  box.className = 'shield-toggle-box'
  box.innerHTML = `
    <div class="shield-toggle-header">
      <span class="shield-icon">🛡️</span>
      <div class="shield-toggle-title">
        <strong>Add TradeDeck Shield</strong>
        <span class="shield-subtitle">AI monitors your project at the 5 moments that determine the outcome</span>
      </div>
      <label class="shield-switch">
        <input type="checkbox" id="shield-toggle-input">
        <span class="shield-slider"></span>
      </label>
    </div>
    <div class="shield-details" id="shield-details" style="display:none">
      <ul class="shield-list">
        <li>Contractor uploads photos at each of 5 AI-designated checkpoints</li>
        <li>AI reviews each upload for quality and code compliance</li>
        <li>You see everything in real time on your Shield dashboard</li>
        <li>Full photo record protects you if anything goes wrong</li>
        <li>Completion report issued on job close</li>
      </ul>
      <div class="shield-price-row">
        <span class="shield-price">$${price}</span>
        <span class="shield-price-note">one-time · best for jobs over $5,000</span>
      </div>
      <button class="shield-pay-btn" id="shield-pay-btn">Add Shield — $${price}</button>
      <p class="shield-contractor-note">
        If your contractor subscribes to Shield Pro, you get Shield free on this job.
      </p>
    </div>
  `

  const toggle  = box.querySelector('#shield-toggle-input')
  const details = box.querySelector('#shield-details')
  const payBtn  = box.querySelector('#shield-pay-btn')

  toggle.addEventListener('change', () => {
    details.style.display = toggle.checked ? 'block' : 'none'
    elected.value = toggle.checked
  })

  payBtn.addEventListener('click', async () => {
    payBtn.disabled = true
    payBtn.textContent = 'Processing…'
    try {
      await purchaseShieldPerJob(jobId, price, jobDescription)
      payBtn.textContent = '✅ Shield Active'
      payBtn.style.background = 'var(--success, #2d7a4f)'
    } catch (err) {
      payBtn.disabled = false
      payBtn.textContent = `Add Shield — $${price}`
      if (err.message !== 'Payment cancelled') alert('Payment failed: ' + err.message)
    }
  })

  container.appendChild(box)
  return { elected }
}

// ─────────────────────────────────────────────────
// PER-JOB PURCHASE — full real Stripe charge
// ─────────────────────────────────────────────────
async function purchaseShieldPerJob(jobId, amount, jobDescription) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) throw new Error('Not signed in')

  if (typeof Stripe === 'undefined') await loadStripeScript()
  const stripe = Stripe(STRIPE_PK)

  // Collect card — opens the bottom-sheet modal
  let paymentMethod
  try {
    paymentMethod = await collectCard(stripe, amount, 'AI milestone monitoring for this job')
  } catch (err) {
    throw err  // 'Payment cancelled' or card error — handled by caller
  }

  // Create PaymentIntent on backend AFTER card collected
  const res = await fetch(`${API_BASE}/shield/create-payment-intent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.access_token}`
    },
    body: JSON.stringify({ job_id: jobId, amount_cents: amount * 100 })
  })
  if (!res.ok) throw new Error('Could not create payment: ' + await res.text())
  const { client_secret } = await res.json()

  // Confirm with the collected PaymentMethod
  const { error: confirmError, paymentIntent } = await stripe.confirmCardPayment(
    client_secret,
    { payment_method: paymentMethod.id }
  )
  if (confirmError) throw new Error(confirmError.message)
  if (paymentIntent.status !== 'succeeded') {
    throw new Error(`Payment status: ${paymentIntent.status}. Please try again.`)
  }

  // Write Shield job to DB — capture the UUID
  const { data: shieldJobRow, error: dbErr } = await sb
    .from('shield_jobs')
    .insert({
      job_id:            jobId,
      homeowner_id:      session.user.id,
      payment_type:      'per_job',
      stripe_payment_id: paymentIntent.id,
      covered_by:        'homeowner',
      status:            'active'
    })
    .select('id')
    .single()
  if (dbErr) throw new Error('Shield activated but DB record failed: ' + dbErr.message)

  const shieldJobId = shieldJobRow.id

  // Insert local points immediately (instant) then sync to backend
  if (jobDescription) {
    const localPoints = getLocalPoints(jobDescription)

    // Write points directly to Supabase (no backend round trip needed)
    const pointRows = localPoints.map((p, i) => ({
      shield_job_id: shieldJobId,
      job_id:        jobId,
      point_number:  i + 1,
      label:         p.label,
      description:   p.description,
    }))

    await sb.from('shield_pivotal_points').insert(pointRows)

    // Also call backend to get Claude-enhanced versions asynchronously
    fetch(`${API_BASE}/shield/generate-points`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.access_token}`
      },
      body: JSON.stringify({
        shield_job_id:   shieldJobId,
        job_id:          jobId,
        job_description: jobDescription
      })
    }).catch(err => console.warn('Shield: backend point enhancement deferred —', err.message))
  }

  return shieldJobId
}

// ─────────────────────────────────────────────────
// CONTRACTOR SUBSCRIPTION ($49/month)
// ─────────────────────────────────────────────────
async function subscribeContractorToShield(containerEl) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) throw new Error('Not signed in')

  const { data: existing } = await sb
    .from('shield_subscriptions')
    .select('id, status, verified_jobs_count, is_verified_contractor')
    .eq('contractor_id', session.user.id)
    .single()

  if (existing && existing.status === 'active') {
    containerEl.innerHTML = `
      <div class="shield-badge-full">
        🛡️ <strong>Shield Pro Active</strong>
        ${existing.is_verified_contractor
          ? '<span class="shield-verified-tag">TradeDeck Verified ✓</span>'
          : `<span class="shield-progress-tag">${existing.verified_jobs_count}/3 verified jobs</span>`
        }
      </div>
    `
    return
  }

  const box = document.createElement('div')
  box.className = 'shield-sub-box'
  box.innerHTML = `
    <div class="shield-sub-header">
      <span class="shield-icon">🛡️</span>
      <strong>TradeDeck Shield Pro</strong>
    </div>
    <ul class="shield-list">
      <li>Shield badge on your profile</li>
      <li>Homeowners on your jobs get Shield free — they'll choose you over the next guy</li>
      <li>AI photo analysis builds your quality portfolio automatically</li>
      <li>Verified completion certificate per job</li>
      <li>Priority placement on Shield job listings</li>
      <li>3 clean completions = TradeDeck Verified Contractor status</li>
    </ul>
    <div class="shield-price-row">
      <span class="shield-price">$${CONTRACTOR_SUB_PRICE}/mo</span>
    </div>
    <button class="shield-pay-btn" id="contractor-sub-btn">
      Subscribe — $${CONTRACTOR_SUB_PRICE}/month
    </button>
  `

  const btn = box.querySelector('#contractor-sub-btn')
  btn.addEventListener('click', async () => {
    btn.disabled = true
    btn.textContent = 'Processing…'
    try {
      const res = await fetch(`${API_BASE}/shield/contractor-subscribe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.access_token}`
        },
        body: JSON.stringify({ contractor_id: session.user.id })
      })
      if (!res.ok) throw new Error(await res.text())
      const { stripe_url } = await res.json()
      window.location.href = stripe_url
    } catch (err) {
      btn.disabled = false
      btn.textContent = `Subscribe — $${CONTRACTOR_SUB_PRICE}/month`
      alert('Subscription error: ' + err.message)
    }
  })

  containerEl.appendChild(box)
}

// ============================================================
// PART 3 — HOMEOWNER DASHBOARD
// ============================================================

async function renderShieldDashboard(containerEl) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) {
    containerEl.innerHTML = '<p class="shield-empty">Sign in to view your Shield jobs.</p>'
    return
  }
  containerEl.innerHTML = '<p class="shield-loading">Loading Shield…</p>'

  const { data: shieldJobs, error } = await sb
    .from('shield_jobs')
    .select(`
      id, status, activated_at, job_id,
      shield_pivotal_points (
        id, point_number, label, description, status,
        shield_photos (
          id, public_url, ai_verdict, ai_confidence, ai_notes, uploaded_at
        )
      )
    `)
    .eq('homeowner_id', session.user.id)
    .order('activated_at', { ascending: false })

  if (error || !shieldJobs?.length) {
    containerEl.innerHTML = `
      <div class="shield-empty">
        <span style="font-size:2rem">🛡️</span>
        <p>No Shield-monitored jobs yet.</p>
        <p style="color:var(--muted)">Add Shield when posting your next job.</p>
      </div>
    `
    return
  }

  containerEl.innerHTML = `<h2 class="shield-dash-title">🛡️ TradeDeck Shield</h2>`

  for (const sj of shieldJobs) {
    const points = (sj.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)
    const completedCount = points.filter(p => p.status === 'approved').length
    const totalPoints    = points.length || 5
    const progressPct   = Math.round((completedCount / totalPoints) * 100)
    const allDone        = completedCount === totalPoints && totalPoints === 5

    const card = document.createElement('div')
    card.className = 'shield-job-card'
    card.innerHTML = `
      <div class="shield-job-header">
        <span class="shield-job-id">Job #${(sj.job_id || '').slice(-6).toUpperCase()}</span>
        <span class="shield-status shield-status--${sj.status}">${sj.status}</span>
      </div>
      <div class="shield-progress-bar-wrap">
        <div class="shield-progress-bar" style="width:${progressPct}%"></div>
      </div>
      <p class="shield-progress-label">${completedCount} of ${totalPoints} checkpoints complete</p>
      <div class="shield-points-list">
        ${points.map(p => renderPointCard(p)).join('')}
      </div>
      ${allDone && sj.status === 'active' ? `
        <button class="shield-closeout-btn" onclick="renderShieldCloseOutModal('${sj.id}')">
          🏁 Close Out This Job
        </button>
      ` : ''}
    `
    containerEl.appendChild(card)
  }
}

function renderPointCard(point) {
  const photo = point.shield_photos?.[0]
  const statusIcon = { pending:'⏳', uploaded:'📸', approved:'✅', flagged:'⚠️' }[point.status] || '⏳'
  const verdictColor = { pass:'#2d7a4f', flag:'#d4a017', fail:'#c0392b' }[photo?.ai_verdict] || 'inherit'

  return `
    <div class="shield-point shield-point--${point.status}">
      <div class="shield-point-header">
        <span class="shield-point-num">${statusIcon} Point ${point.point_number}</span>
        <span class="shield-point-label">${point.label}</span>
      </div>
      <p class="shield-point-desc">${point.description}</p>
      ${photo ? `
        <div class="shield-photo-block">
          <img class="shield-photo-thumb" src="${photo.public_url}" alt="Checkpoint photo" />
          <div class="shield-ai-verdict" style="color:${verdictColor}">
            <strong>AI: ${photo.ai_verdict?.toUpperCase() || '—'}</strong>
            ${photo.ai_confidence ? `<span>(${Math.round(photo.ai_confidence * 100)}%)</span>` : ''}
          </div>
          ${photo.ai_notes ? `<p class="shield-ai-notes">${photo.ai_notes}</p>` : ''}
        </div>
      ` : `<p class="shield-awaiting">Awaiting contractor photo upload</p>`}
    </div>
  `
}

// ============================================================
// PART 4 — CONTRACTOR PHOTO UPLOAD
// ============================================================

// ─────────────────────────────────────────────────
// SHIELD PHOTO VALIDATION HELPERS
// GPS, EXIF, and originality enforcement
// ─────────────────────────────────────────────────

/** Request GPS from browser. Returns {lat, lng, accuracy} or throws. */
function getGpsLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('GPS is not available on this device.'))
      return
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve({
        lat:      pos.coords.latitude,
        lng:      pos.coords.longitude,
        accuracy: pos.coords.accuracy   // metres
      }),
      err => {
        const msgs = {
          1: 'Location permission denied. Enable GPS in your browser settings to upload Shield photos.',
          2: 'Could not get GPS signal. Step outside or check your signal and try again.',
          3: 'GPS timed out. Try again.'
        }
        reject(new Error(msgs[err.code] || 'GPS error.'))
      },
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
    )
  })
}

/** Compute SHA-256 hash of a File using Web Crypto API.
 *  Returns hex string. Used for tamper-evident chain of custody. */
async function computeSHA256(file) {
  const buf    = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Read EXIF data from a File. Returns parsed tags or empty object. */
function readExif(file) {
  return new Promise(resolve => {
    // Use FileReader to get ArrayBuffer, then parse EXIF manually (lightweight)
    const reader = new FileReader()
    reader.onload = e => {
      try {
        const buf  = e.target.result
        const view = new DataView(buf)
        // JPEG starts with FFD8
        if (view.getUint16(0) !== 0xFFD8) { resolve({}); return }
        const tags = {}
        let offset = 2
        while (offset < buf.byteLength - 2) {
          const marker = view.getUint16(offset)
          offset += 2
          if (marker === 0xFFE1) {   // APP1 — EXIF block
            const segLen = view.getUint16(offset)
            const exifStr = String.fromCharCode(...new Uint8Array(buf, offset + 2, 6))
            if (exifStr.startsWith('Exif')) {
              // We have EXIF — note its presence and rough size
              tags.hasExif     = true
              tags.exifBytes   = segLen
              // Check for DateTimeOriginal marker (0x9003) — presence indicates camera metadata
              const segData = new Uint8Array(buf, offset, segLen)
              tags.hasDateTime = segData.includes(0x90) // rough heuristic
            }
            offset += segLen
          } else if ((marker & 0xFF00) === 0xFF00) {
            if (offset + 1 >= buf.byteLength) break
            offset += view.getUint16(offset)
          } else {
            break
          }
        }
        resolve(tags)
      } catch {
        resolve({})
      }
    }
    reader.onerror = () => resolve({})
    reader.readAsArrayBuffer(file)
  })
}

/** Check if file looks like a screenshot or re-photo of a screen */
function checkOriginality(file, exifTags) {
  const issues = []
  // Screenshots typically have no EXIF at all
  if (!exifTags.hasExif) {
    issues.push('No camera metadata found — this may be a screenshot or downloaded image.')
  }
  // PNG is almost always a screenshot (real cameras save JPEG)
  if (file.type === 'image/png') {
    issues.push('PNG format detected. Shield requires a direct camera photo (JPEG/HEIC), not a screenshot.')
  }
  // Very small file size for an "on-site" photo is suspicious
  if (file.size < 150 * 1024) {   // under 150KB
    issues.push('Photo file size is unusually small for an on-site construction photo.')
  }
  return issues
}

async function renderContractorUploadFlow(containerEl, shieldJobId, pointId) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) { containerEl.innerHTML = '<p style="color:var(--steel)">Sign in to upload.</p>'; return }

  // Load pivotal points if no specific pointId given
  let points = []
  if (!pointId) {
    const { data } = await sb
      .from('shield_pivotal_points')
      .select('id, point_number, label, description, status')
      .eq('shield_job_id', shieldJobId)
      .order('point_number')
    points = data || []
  }

  const box = document.createElement('div')
  box.className = 'shield-upload-box'

  const pointsHtml = points.length > 0
    ? points.map(p => `
        <div class="shield-point-row" data-point-id="${p.id}" style="border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px;margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <span style="font-family:'Barlow Condensed',sans-serif;font-weight:700;font-size:0.85rem;color:var(--white);">${p.point_number}. ${p.label}</span>
            <span class="shield-point-status" style="font-size:0.7rem;padding:2px 8px;border-radius:4px;background:${p.status === 'approved' ? 'rgba(74,222,128,0.15)' : 'rgba(245,158,11,0.12)'};color:${p.status === 'approved' ? '#4ADE80' : 'var(--amber)'};">${p.status || 'pending'}</span>
          </div>
          <div style="font-size:0.78rem;color:var(--steel);margin-bottom:10px;">${p.description}</div>
          ${p.status === 'approved'
            ? '<div style="font-size:0.78rem;color:#4ADE80;">✓ Photo approved</div>'
            : `<div style="font-size:0.72rem;color:rgba(255,255,255,0.35);margin-bottom:6px;">
                  📋 Take a wide shot (whole area) then a close-up detail shot. Both required.
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:6px 10px;">
                    <span style="font-size:0.78rem;color:var(--amber);font-weight:600;">📷 Wide Shot</span>
                    <input type="file" class="shield-point-file shield-wide-file" accept="image/jpeg,image/heic,image/heif" capture="environment" style="display:none;" data-point-id="${p.id}" data-shot-type="wide" />
                  </label>
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:6px 10px;">
                    <span style="font-size:0.78rem;color:var(--amber);font-weight:600;">🔍 Detail Shot</span>
                    <input type="file" class="shield-point-file shield-detail-file" accept="image/jpeg,image/heic,image/heif" capture="environment" style="display:none;" data-point-id="${p.id}" data-shot-type="detail" />
                  </label>
                </div>
                <div class="shield-point-status-msg" style="margin-top:8px;font-size:0.78rem;"></div>`
          }
        </div>`).join('')
    : `<div style="font-size:0.85rem;color:var(--steel);padding:12px 0;">Loading checkpoints…</div>`

  box.innerHTML = `
    <div style="margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:0.85rem;">📍</span>
        <span id="shield-gps-status" style="font-size:0.78rem;color:var(--steel);">Requesting GPS location…</span>
      </div>
      <div style="font-size:0.72rem;color:rgba(255,255,255,0.3);">GPS is required for all Shield photos. Enable location in your browser.</div>
    </div>
    <div id="shield-points-list">${pointsHtml}</div>
  `
  containerEl.appendChild(box)

  // ── Get GPS first ──
  const gpsStatusEl = box.querySelector('#shield-gps-status')
  let gpsData = null
  try {
    gpsData = await getGpsLocation()
    gpsStatusEl.textContent = `✅ GPS locked (±${Math.round(gpsData.accuracy)}m)`
    gpsStatusEl.style.color = '#4ADE80'
  } catch (err) {
    gpsStatusEl.textContent = '❌ ' + err.message
    gpsStatusEl.style.color = '#EF4444'
    // Block uploads — GPS required
    box.querySelectorAll('.shield-point-file').forEach(inp => inp.disabled = true)
    return
  }

  // ── Wire up each checkpoint file input ──
  box.querySelectorAll('.shield-point-file').forEach(fileInput => {
    fileInput.addEventListener('change', async function() {
      const file      = this.files[0]
      if (!file) return
      const thisPointId = this.dataset.pointId
      const shotType    = this.dataset.shotType || 'detail'  // 'wide' or 'detail'
      const row         = box.querySelector(`.shield-point-row[data-point-id="${thisPointId}"]`)
      const statusMsg   = row.querySelector('.shield-point-status-msg')
      const statusBadge = row.querySelector('.shield-point-status')

      statusMsg.style.color = 'var(--steel)'
      statusMsg.textContent = '🔍 Checking photo…'

      // ── Layer 1: EXIF + Originality ──
      const exifTags = await readExif(file)
      const issues   = checkOriginality(file, exifTags)
      if (issues.length > 0) {
        statusMsg.style.color = '#EF4444'
        statusMsg.innerHTML = '❌ ' + issues.join('<br>❌ ')
        this.value = ''
        return
      }

      // ── Layer 2: Compute SHA-256 hash (tamper-evident proof of file contents) ──
      statusMsg.textContent = '🔒 Computing integrity hash…'
      let fileHash = null
      try {
        fileHash = await computeSHA256(file)
      } catch (hashErr) {
        console.warn('SHA-256 failed (non-blocking):', hashErr)
      }

      statusMsg.textContent = '📤 Uploading…'

      try {
        const ts   = Date.now()
        const path = `shield-photos/${shieldJobId}/${thisPointId}/${ts}_${shotType}_${file.name}`

        const { error: storageErr } = await sb.storage
          .from('draw-photos')
          .upload(path, file, { contentType: file.type })
        if (storageErr) throw new Error(storageErr.message)

        const { data: { publicUrl } } = sb.storage.from('draw-photos').getPublicUrl(path)

        // ── Store photo with full chain-of-custody metadata ──
        const photoInsert = {
          point_id:        thisPointId,
          shield_job_id:   shieldJobId,
          contractor_id:   session.user.id,
          storage_path:    path,
          public_url:      publicUrl,
          gps_lat:         gpsData.lat,
          gps_lng:         gpsData.lng,
          gps_accuracy_m:  gpsData.accuracy,
          has_exif:        exifTags.hasExif || false,
          file_size_bytes: file.size,
          captured_at:     new Date(ts).toISOString(),
          device_user_agent: navigator.userAgent,
        }
        if (fileHash) {
          photoInsert.photo_hash      = fileHash
          photoInsert.hash_algorithm  = 'SHA-256'
        }
        // Store wide vs detail shot in correct column
        if (shotType === 'wide')   photoInsert.wide_shot_url   = publicUrl
        if (shotType === 'detail') photoInsert.detail_shot_url = publicUrl

        const { data: photoRow, error: dbErr } = await sb
          .from('shield_photos')
          .insert(photoInsert)
          .select('id')
          .single()
        if (dbErr) throw new Error(dbErr.message)

        // ── Only run AI analysis on the detail shot ──
        // (Wide shot is just an anchor — AI judges the detail)
        if (shotType === 'wide') {
          statusMsg.style.color = '#4ADE80'
          statusMsg.textContent = '✅ Wide shot saved. Now take the detail shot.'
          return
        }

        statusMsg.textContent = '🤖 Running AI analysis…'

        const analysisRes = await fetch(`${API_BASE}/shield/analyze-photo`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}`
          },
          body: JSON.stringify({
            photo_id:    photoRow.id,
            public_url:  publicUrl,
            point_id:    thisPointId,
            gps_lat:     gpsData.lat,
            gps_lng:     gpsData.lng,
            has_exif:    exifTags.hasExif || false,
            photo_hash:  fileHash,
            shot_type:   shotType,
          })
        })
        if (!analysisRes.ok) throw new Error('AI analysis failed')
        const result = await analysisRes.json()
        const { verdict, confidence, notes, authentic } = result

        const colors = { pass: '#4ADE80', flag: '#F59E0B', fail: '#EF4444', fake: '#EF4444' }
        const icons  = { pass: '✅', flag: '⚠️', fail: '❌', fake: '🚫' }
        statusMsg.style.color = colors[verdict] || 'var(--steel)'
        statusMsg.innerHTML = `
          ${icons[verdict] || '?'} <strong>${verdict.toUpperCase()}</strong> (${Math.round(confidence * 100)}% confidence)<br>
          <span style="opacity:0.85">${notes}</span>
        `
        if (statusBadge) {
          statusBadge.textContent = verdict
          statusBadge.style.background = verdict === 'pass' ? 'rgba(74,222,128,0.15)' : 'rgba(245,158,11,0.12)'
          statusBadge.style.color = colors[verdict]
        }

      } catch (err) {
        statusMsg.style.color = '#EF4444'
        statusMsg.textContent = '❌ ' + err.message
        this.value = ''
      }
    })
  })
}

// ============================================================
// PART 5 — CLOSE-OUT SYSTEM
// Tamper-evident SHA-256 completion packet
// ============================================================

async function renderShieldCloseOutModal(shieldJobId) {
  const { data: { session } } = await sb.auth.getSession()
  if (!session) return

  // Fetch everything needed for the packet
  const { data: shieldJob } = await sb
    .from('shield_jobs')
    .select(`
      id, job_id, homeowner_id, payment_type, stripe_payment_id,
      status, activated_at,
      shield_pivotal_points (
        id, point_number, label, description, status,
        shield_photos (
          id, public_url, ai_verdict, ai_confidence, ai_notes, uploaded_at
        )
      )
    `)
    .eq('id', shieldJobId)
    .single()

  if (!shieldJob) { alert('Could not load Shield job data.'); return }

  const points        = (shieldJob.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)
  const approvedCount = points.filter(p => p.status === 'approved').length
  const allApproved   = approvedCount === 5

  // Build modal
  const overlay = document.createElement('div')
  overlay.id = 'shield-closeout-overlay'
  overlay.innerHTML = `
    <div class="scm-backdrop"></div>
    <div class="scm-sheet" style="max-height:85vh;overflow-y:auto">
      <div class="scm-handle"></div>
      <div class="scm-header">
        <span class="shield-icon">🏁</span>
        <div class="scm-title-group">
          <strong class="scm-title">Close Out This Job</strong>
          <span class="scm-desc">Creates a tamper-evident completion record</span>
        </div>
      </div>

      <div class="shield-closeout-summary">
        <p>${approvedCount}/5 checkpoints approved</p>
        ${!allApproved ? `
          <div class="shield-closeout-warning">
            ⚠️ Not all checkpoints are approved.
            <label class="shield-closeout-override">
              <input type="checkbox" id="closeout-override" />
              Close anyway
            </label>
          </div>
        ` : '<p class="shield-feedback-ok">✅ All checkpoints approved</p>'}
      </div>

      <div class="shield-closeout-points">
        ${points.map(p => {
          const photo = p.shield_photos?.[0]
          return `
            <div class="shield-closeout-point shield-closeout-point--${p.status}">
              <span>${p.point_number}. ${p.label}</span>
              <span class="shield-closeout-verdict">
                ${photo ? photo.ai_verdict?.toUpperCase() : 'NO PHOTO'}
              </span>
            </div>
          `
        }).join('')}
      </div>

      <p id="closeout-status" class="shield-upload-status"></p>

      <button class="scm-submit-btn" id="closeout-confirm-btn"
        ${!allApproved ? 'disabled' : ''}>
        Generate Completion Record
      </button>
      <button class="scm-cancel-btn" id="closeout-cancel-btn">Cancel</button>
    </div>
  `

  document.body.appendChild(overlay)
  requestAnimationFrame(() => overlay.classList.add('scm-visible'))

  function closeModal() {
    overlay.classList.remove('scm-visible')
    overlay.addEventListener('transitionend', () => overlay.remove(), { once: true })
  }

  overlay.querySelector('.scm-backdrop').addEventListener('click', closeModal)
  overlay.querySelector('#closeout-cancel-btn').addEventListener('click', closeModal)

  // Enable confirm button if override is checked
  const overrideCheck = overlay.querySelector('#closeout-override')
  const confirmBtn    = overlay.querySelector('#closeout-confirm-btn')
  if (overrideCheck) {
    overrideCheck.addEventListener('change', () => {
      confirmBtn.disabled = !overrideCheck.checked
    })
  }

  confirmBtn.addEventListener('click', async () => {
    confirmBtn.disabled = true
    confirmBtn.textContent = 'Generating record…'
    const statusEl = overlay.querySelector('#closeout-status')

    try {
      await generateCloseOutRecord(shieldJob, session)
      statusEl.textContent = '✅ Completion record created and emailed.'
      statusEl.style.color = '#2d7a4f'
      confirmBtn.textContent = 'Done'

      // Refresh the dashboard after 2 seconds
      setTimeout(() => { closeModal(); renderShieldDashboard(document.querySelector('#shield-dashboard-root') || document.body) }, 2000)
    } catch (err) {
      confirmBtn.disabled = false
      confirmBtn.textContent = 'Generate Completion Record'
      statusEl.textContent = 'Error: ' + err.message
      statusEl.style.color = '#c0392b'
    }
  })
}

async function generateCloseOutRecord(shieldJob, session) {
  const points = (shieldJob.shield_pivotal_points || []).sort((a, b) => a.point_number - b.point_number)

  // Build the completion packet
  const packet = {
    shield_job_id:    shieldJob.id,
    job_id:           shieldJob.job_id,
    homeowner_id:     shieldJob.homeowner_id,
    payment_type:     shieldJob.payment_type,
    stripe_payment_id: shieldJob.stripe_payment_id,
    activated_at:     shieldJob.activated_at,
    closed_at:        new Date().toISOString(),
    closed_by:        session.user.id,
    points: points.map(p => ({
      point_number: p.point_number,
      label:        p.label,
      description:  p.description,
      status:       p.status,
      photo:        p.shield_photos?.[0] ? {
        public_url:    p.shield_photos[0].public_url,
        ai_verdict:    p.shield_photos[0].ai_verdict,
        ai_confidence: p.shield_photos[0].ai_confidence,
        ai_notes:      p.shield_photos[0].ai_notes,
        uploaded_at:   p.shield_photos[0].uploaded_at,
      } : null
    }))
  }

  // SHA-256 hash the packet — makes it tamper-evident
  const packetString = JSON.stringify(packet)
  const hashBuffer   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(packetString))
  const hashHex      = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')

  const fullRecord = { ...packet, sha256: hashHex }

  // Send to backend for storage + email
  const res = await fetch(`${API_BASE}/shield/complete-job`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.access_token}`
    },
    body: JSON.stringify(fullRecord)
  })
  if (!res.ok) throw new Error(await res.text())

  // Mark shield_job as complete in Supabase
  await sb.from('shield_jobs').update({ status: 'complete', completed_at: new Date().toISOString() }).eq('id', shieldJob.id)

  return fullRecord
}

// ============================================================
// PART 6 — SHIELD BADGE (contractor profile)
// ============================================================

async function renderShieldBadge(contractorId, containerEl) {
  const { data: sub } = await sb
    .from('shield_subscriptions')
    .select('status, is_verified_contractor, verified_jobs_count')
    .eq('contractor_id', contractorId)
    .single()

  if (!sub || sub.status !== 'active') return

  const badge = document.createElement('div')
  badge.className = 'shield-badge'
  badge.innerHTML = sub.is_verified_contractor
    ? `🛡️ <strong>TradeDeck Verified Contractor</strong>`
    : `🛡️ <strong>Shield Pro</strong> · ${sub.verified_jobs_count}/3 verified jobs`
  containerEl.appendChild(badge)
}

// ============================================================
// PART 7 — CARD COLLECTION MODAL (real Stripe Elements)
// ============================================================

function collectCard(stripe, amount, description) {
  return new Promise((resolve, reject) => {
    const overlay = document.createElement('div')
    overlay.id = 'shield-card-overlay'
    overlay.innerHTML = `
      <div class="scm-backdrop"></div>
      <div class="scm-sheet" role="dialog" aria-modal="true" aria-label="Payment">
        <div class="scm-handle"></div>
        <div class="scm-header">
          <span class="scm-icon">🛡️</span>
          <div class="scm-title-group">
            <strong class="scm-title">TradeDeck Shield</strong>
            <span class="scm-desc">${description || 'AI milestone monitoring'}</span>
          </div>
          <span class="scm-amount">$${amount}</span>
        </div>
        <div class="scm-section-label">Card details</div>
        <div id="scm-card-element" class="scm-card-input"></div>
        <div id="scm-card-error" class="scm-error" role="alert"></div>
        <div class="scm-secure-note">
          <span class="scm-lock">🔒</span>
          Secured by Stripe · Your card is never stored on TradeDeck servers
        </div>
        <button class="scm-submit-btn" id="scm-submit-btn">Pay $${amount}</button>
        <button class="scm-cancel-btn" id="scm-cancel-btn">Cancel</button>
      </div>
    `
    document.body.appendChild(overlay)
    requestAnimationFrame(() => overlay.classList.add('scm-visible'))

    const elements = stripe.elements()
    const cardEl   = elements.create('card', {
      style: {
        base: {
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          fontSize: '16px',
          color: '#1a1a1a',
          '::placeholder': { color: '#aab7c4' },
        },
        invalid: { color: '#c0392b', iconColor: '#c0392b' },
      },
      hidePostalCode: false,
    })
    cardEl.mount('#scm-card-element')
    cardEl.on('change', ({ error }) => {
      document.getElementById('scm-card-error').textContent = error ? error.message : ''
    })

    function closeModal() {
      overlay.classList.remove('scm-visible')
      overlay.addEventListener('transitionend', () => overlay.remove(), { once: true })
      cardEl.destroy()
    }

    document.getElementById('scm-cancel-btn').addEventListener('click', () => {
      closeModal()
      reject(new Error('Payment cancelled'))
    })
    overlay.querySelector('.scm-backdrop').addEventListener('click', () => {
      closeModal()
      reject(new Error('Payment cancelled'))
    })

    const submitBtn = document.getElementById('scm-submit-btn')
    submitBtn.addEventListener('click', async () => {
      submitBtn.disabled = true
      submitBtn.textContent = 'Processing…'
      document.getElementById('scm-card-error').textContent = ''

      const { paymentMethod, error } = await stripe.createPaymentMethod({ type: 'card', card: cardEl })
      if (error) {
        document.getElementById('scm-card-error').textContent = error.message
        submitBtn.disabled = false
        submitBtn.textContent = `Pay $${amount}`
        return
      }
      closeModal()
      resolve(paymentMethod)
    })
  })
}

// ============================================================
// PART 8 — CSS
// ============================================================

const SHIELD_CSS = `
/* ── Base ─────────────────────────────────────── */
.shield-toggle-box, .shield-sub-box {
  border: 1px solid var(--brass, #b8860b);
  border-radius: 0.75rem;
  padding: 1rem;
  margin: 1rem 0;
  background: var(--surface, #fff);
}
.shield-toggle-header, .shield-sub-header {
  display: flex; align-items: center; gap: 0.75rem;
}
.shield-icon { font-size: 1.5rem; flex-shrink: 0; }
.shield-toggle-title { flex: 1; }
.shield-toggle-title strong { display: block; font-size: 0.95rem; color: var(--brass, #b8860b); }
.shield-subtitle { font-size: 0.78rem; color: var(--muted, #666); }
.shield-list { padding-left: 1.25rem; margin: 0.5rem 0; font-size: 0.85rem; }
.shield-list li { margin-bottom: 0.35rem; }
.shield-price-row { display: flex; align-items: baseline; gap: 0.5rem; margin: 0.75rem 0; }
.shield-price { font-size: 1.5rem; font-weight: 700; color: var(--spruce, #2d5a4f); }
.shield-price-note { font-size: 0.78rem; color: var(--muted, #666); }
.shield-pay-btn {
  width: 100%; padding: 0.75rem;
  background: var(--brass, #b8860b); color: white;
  border: none; border-radius: 0.5rem;
  font-size: 0.95rem; font-weight: 600; cursor: pointer;
}
.shield-pay-btn:disabled { opacity: 0.6; cursor: default; }
.shield-contractor-note { font-size: 0.75rem; color: var(--muted, #666); margin-top: 0.5rem; text-align: center; }

/* ── Toggle Switch ────────────────────────────── */
.shield-switch { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
.shield-switch input { opacity: 0; width: 0; height: 0; }
.shield-slider { position: absolute; inset: 0; border-radius: 34px; background: #ccc; cursor: pointer; transition: 0.3s; }
.shield-slider:before { content: ''; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; border-radius: 50%; background: white; transition: 0.3s; }
.shield-switch input:checked + .shield-slider { background: var(--brass, #b8860b); }
.shield-switch input:checked + .shield-slider:before { transform: translateX(20px); }

/* ── Dashboard ────────────────────────────────── */
.shield-dash-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.75rem; }
.shield-job-card { border: 1px solid var(--border, #ddd); border-radius: 0.75rem; padding: 0.9rem; margin-bottom: 1rem; }
.shield-job-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
.shield-job-id { font-weight: 600; font-size: 0.85rem; }
.shield-status { font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 1rem; font-weight: 600; }
.shield-status--active  { background: #e6f4ec; color: #2d7a4f; }
.shield-status--complete { background: #e8f0fe; color: #1a56db; }
.shield-progress-bar-wrap { height: 6px; background: var(--border, #ddd); border-radius: 3px; margin: 0.5rem 0; }
.shield-progress-bar { height: 6px; background: var(--brass, #b8860b); border-radius: 3px; transition: width 0.4s; }
.shield-progress-label { font-size: 0.78rem; color: var(--muted, #666); margin-bottom: 0.5rem; }
.shield-point { border: 1px solid var(--border, #eee); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; }
.shield-point--approved { border-color: #2d7a4f; background: #f0faf4; }
.shield-point--flagged  { border-color: #d4a017; background: #fffbec; }
.shield-point-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; }
.shield-point-num { font-size: 0.75rem; font-weight: 700; }
.shield-point-label { font-size: 0.85rem; font-weight: 600; }
.shield-point-desc { font-size: 0.78rem; color: var(--muted, #666); margin: 0.25rem 0; }
.shield-photo-thumb { width: 100%; border-radius: 0.4rem; margin: 0.5rem 0; max-height: 200px; object-fit: cover; }
.shield-ai-verdict { font-size: 0.85rem; }
.shield-ai-notes { font-size: 0.78rem; color: var(--muted, #666); }
.shield-awaiting { font-size: 0.78rem; color: var(--muted, #666); font-style: italic; }
.shield-empty { text-align: center; padding: 2rem; color: var(--muted, #666); }
.shield-closeout-btn {
  width: 100%; margin-top: 0.75rem; padding: 0.65rem;
  background: var(--spruce, #2d5a4f); color: white;
  border: none; border-radius: 0.5rem; font-size: 0.88rem; font-weight: 600; cursor: pointer;
}

/* ── Badge ────────────────────────────────────── */
.shield-badge {
  display: inline-flex; align-items: center; gap: 0.4rem;
  background: #fffbec; border: 1px solid var(--brass, #b8860b);
  color: var(--brass, #b8860b); border-radius: 1rem;
  padding: 0.25rem 0.75rem; font-size: 0.78rem;
}
.shield-badge-full { padding: 0.75rem; background: #fffbec; border-radius: 0.5rem; border: 1px solid var(--brass, #b8860b); }
.shield-verified-tag { margin-left: 0.5rem; color: #2d7a4f; font-weight: 600; font-size: 0.82rem; }
.shield-progress-tag { margin-left: 0.5rem; color: var(--muted, #888); font-size: 0.82rem; }

/* ── Upload ───────────────────────────────────── */
.shield-upload-box { margin: 0.75rem 0; }
.shield-upload-label { font-size: 0.85rem; font-weight: 600; margin-bottom: 0.5rem; }
.shield-upload-status { margin-top: 0.5rem; font-size: 0.82rem; }

/* ── Brief Engine ─────────────────────────────── */
.shield-brief-wrap { margin: 1rem 0; }
.shield-brief-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
.shield-brief-title { display: block; font-size: 0.95rem; font-weight: 700; color: var(--brass, #b8860b); }
.shield-brief-sub { font-size: 0.78rem; color: var(--muted, #666); }
.shield-brief-textarea {
  width: 100%; box-sizing: border-box;
  border: 1.5px solid var(--border, #ddd); border-radius: 0.6rem;
  padding: 0.75rem; font-size: 0.9rem; line-height: 1.5;
  resize: vertical; font-family: inherit;
}
.shield-brief-textarea:focus { outline: none; border-color: var(--brass, #b8860b); }
.shield-score-bar-wrap { height: 6px; background: #eee; border-radius: 3px; margin: 0.5rem 0; }
.shield-score-bar { height: 6px; border-radius: 3px; transition: width 0.4s, background 0.4s; }
.shield-brief-feedback { font-size: 0.82rem; margin: 0.4rem 0; }
.shield-feedback-list { margin: 0; padding-left: 1.1rem; color: var(--muted, #777); }
.shield-feedback-ok { color: #2d7a4f; margin: 0; }
.shield-questions-label { font-size: 0.8rem; font-weight: 600; margin: 0.5rem 0 0.25rem; }
.shield-questions-list { padding-left: 1.1rem; font-size: 0.8rem; color: var(--muted, #666); margin: 0; }
.shield-points-label { font-size: 0.8rem; font-weight: 600; margin: 0.75rem 0 0.4rem; }
.shield-brief-points-preview { margin: 0.5rem 0; }
.shield-point-preview {
  display: flex; gap: 0.6rem; align-items: flex-start;
  padding: 0.5rem 0; border-bottom: 1px solid #f0f0f0;
  font-size: 0.82rem;
}
.shield-point-preview:last-child { border-bottom: none; }
.shield-point-num-sm {
  flex-shrink: 0; width: 1.4rem; height: 1.4rem;
  background: var(--brass, #b8860b); color: white;
  border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-size: 0.7rem; font-weight: 700;
}
.shield-point-preview p { margin: 0.15rem 0 0; color: var(--muted, #666); }

/* ── Close-out ────────────────────────────────── */
.shield-closeout-summary { margin-bottom: 0.75rem; font-size: 0.88rem; }
.shield-closeout-warning { background: #fff8ec; border: 1px solid #d4a017; border-radius: 0.4rem; padding: 0.6rem; margin-top: 0.4rem; font-size: 0.82rem; }
.shield-closeout-override { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem; cursor: pointer; }
.shield-closeout-points { margin-bottom: 1rem; }
.shield-closeout-point { display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid #f0f0f0; font-size: 0.82rem; }
.shield-closeout-point--approved .shield-closeout-verdict { color: #2d7a4f; font-weight: 600; }
.shield-closeout-point--flagged .shield-closeout-verdict  { color: #d4a017; font-weight: 600; }
.shield-closeout-point--pending .shield-closeout-verdict  { color: #888; }

/* ── Card Modal ───────────────────────────────── */
#shield-card-overlay, #shield-closeout-overlay {
  position: fixed; inset: 0; z-index: 9000;
  display: flex; flex-direction: column; justify-content: flex-end;
  pointer-events: none;
}
#shield-card-overlay.scm-visible, #shield-closeout-overlay.scm-visible { pointer-events: all; }
.scm-backdrop {
  position: absolute; inset: 0;
  background: rgba(0,0,0,0); transition: background 0.3s ease; cursor: pointer;
}
#shield-card-overlay.scm-visible .scm-backdrop,
#shield-closeout-overlay.scm-visible .scm-backdrop { background: rgba(0,0,0,0.55); }
.scm-sheet {
  position: relative; background: #fff;
  border-radius: 1.25rem 1.25rem 0 0;
  padding: 1.25rem 1.25rem 2rem;
  max-width: 480px; width: 100%; margin: 0 auto;
  transform: translateY(100%);
  transition: transform 0.35s cubic-bezier(0.32,0.72,0,1);
  box-shadow: 0 -4px 32px rgba(0,0,0,0.15);
}
#shield-card-overlay.scm-visible .scm-sheet,
#shield-closeout-overlay.scm-visible .scm-sheet { transform: translateY(0); }
.scm-handle { width: 40px; height: 4px; background: #ddd; border-radius: 2px; margin: 0 auto 1rem; }
.scm-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid #eee; }
.scm-icon { font-size: 1.5rem; flex-shrink: 0; }
.scm-title-group { flex: 1; }
.scm-title { display: block; font-size: 0.95rem; font-weight: 700; color: var(--brass, #b8860b); }
.scm-desc { font-size: 0.75rem; color: var(--muted, #777); }
.scm-amount { font-size: 1.4rem; font-weight: 700; color: var(--spruce, #2d5a4f); flex-shrink: 0; }
.scm-section-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted, #888); margin-bottom: 0.5rem; }
.scm-card-input { border: 1.5px solid #d1d5db; border-radius: 0.6rem; padding: 0.85rem 0.9rem; background: #fafafa; transition: border-color 0.2s; margin-bottom: 0.5rem; }
.scm-card-input.StripeElement--focus { border-color: var(--brass, #b8860b); background: #fff; }
.scm-card-input.StripeElement--invalid { border-color: #c0392b; }
.scm-error { min-height: 1.2rem; font-size: 0.8rem; color: #c0392b; margin-bottom: 0.75rem; }
.scm-secure-note { display: flex; align-items: center; gap: 0.35rem; font-size: 0.73rem; color: var(--muted, #888); margin-bottom: 1rem; }
.scm-submit-btn {
  width: 100%; padding: 0.9rem;
  background: var(--brass, #b8860b); color: #fff;
  border: none; border-radius: 0.65rem;
  font-size: 1rem; font-weight: 700; cursor: pointer;
  transition: opacity 0.2s, transform 0.1s; margin-bottom: 0.6rem;
}
.scm-submit-btn:hover:not(:disabled) { opacity: 0.92; }
.scm-submit-btn:active:not(:disabled) { transform: scale(0.98); }
.scm-submit-btn:disabled { opacity: 0.6; cursor: default; }
.scm-cancel-btn { width: 100%; padding: 0.6rem; background: none; border: none; color: var(--muted, #888); font-size: 0.88rem; cursor: pointer; }
.scm-cancel-btn:hover { color: #333; }
`

// Inject CSS once on load
;(function injectShieldCSS() {
  if (document.getElementById('shield-styles')) return
  const style = document.createElement('style')
  style.id = 'shield-styles'
  style.textContent = SHIELD_CSS
  document.head.appendChild(style)
})()

// Expose functions globally for onclick attributes and external calls
window.renderShieldBrief              = renderShieldBrief
window.renderShieldToggle             = renderShieldToggle
window.purchaseShieldPerJob           = purchaseShieldPerJob
window.subscribeContractorToShield    = subscribeContractorToShield
window.renderShieldDashboard          = renderShieldDashboard
window.renderContractorUploadFlow     = renderContractorUploadFlow
window.renderShieldBadge              = renderShieldBadge
window.renderShieldCloseOutModal      = renderShieldCloseOutModal
