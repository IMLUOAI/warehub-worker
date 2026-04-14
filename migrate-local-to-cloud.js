/**
 * WAREHUB — One-Time localStorage → D1 Migration Script
 * ======================================================
 * Run this in the browser console while signed in to Warehub.
 * It reads all your existing localStorage data and pushes it
 * to the Worker API so D1 becomes the primary source of truth.
 *
 * USAGE:
 *   1. Open warehub-app (imluoai.github.io/warehub-app)
 *   2. Sign in with Clerk
 *   3. Open DevTools → Console
 *   4. Paste this entire script and press Enter
 *   5. Watch the log — green checkmarks mean success
 *
 * Safe to re-run — all endpoints are idempotent (upsert, not duplicate).
 */

(async function migrateLocalToCloud() {
  const LINE = '─'.repeat(50);

  function log(msg, color) {
    const colors = { green: '#4ade80', yellow: '#facc15', red: '#f87171', cyan: '#67e8f9', white: '#e5e7eb' };
    console.log('%c' + msg, 'color:' + (colors[color] || colors.white));
  }

  log(LINE, 'cyan');
  log('  WAREHUB  localStorage → D1  Migration', 'cyan');
  log(LINE, 'cyan');

  // ── Pre-flight checks ──────────────────────────────────────────────
  if (!window.warehubApi || !window._clerkToken) {
    log('✗ Not signed in or API not ready. Please sign in to Warehub first.', 'red');
    return;
  }
  if (!window.apiSavePackers) {
    log('✗ API sync layer not loaded. Make sure you\'re on the latest version.', 'red');
    return;
  }

  let ok = 0, fail = 0;

  async function call(method, path, body) {
    try {
      const r = await window.warehubApi(method, path, body);
      return r;
    } catch(e) {
      log('  ✗ ' + method + ' ' + path + ': ' + e.message, 'red');
      fail++;
      return null;
    }
  }

  // ── 1. PACKERS & MANAGERS ──────────────────────────────────────────
  log('\n[1/6] Packers & Managers', 'yellow');
  try {
    const ps = JSON.parse(localStorage.getItem('warehub_packers')  || '[]');
    const ms = JSON.parse(localStorage.getItem('warehub_managers') || '[]');
    const all = ps.concat(ms);
    if (!all.length) {
      log('  · No packers in localStorage — skipping', 'white');
    } else {
      const r = await call('POST', '/api/packers/sync', { packers: all });
      if (r && r.ok) {
        log('  ✓ Synced ' + all.length + ' packers/managers', 'green');
        ok++;
      } else {
        log('  ✗ Packer sync failed: ' + JSON.stringify(r), 'red');
        fail++;
      }
    }
  } catch(e) {
    log('  ✗ Packer parse error: ' + e.message, 'red');
    fail++;
  }

  // ── 2. RETURNS ─────────────────────────────────────────────────────
  log('\n[2/6] Returns', 'yellow');
  try {
    const list = JSON.parse(localStorage.getItem('warehub_returns') || '[]');
    if (!list.length) {
      log('  · No returns in localStorage — skipping', 'white');
    } else {
      let saved = 0;
      for (const entry of list) {
        const r = await call('POST', '/api/returns', {
          tracking:    entry.tracking    || null,
          carrier:     entry.carrier     || null,
          type:        entry.type        || null,
          condition:   entry.condition   || null,
          sku:         entry.sku         || null,
          qty:         entry.qty         || 1,
          pile:        entry.pile        || null,
          location:    entry.location    || null,
          notes:       entry.notes       || null,
          scanned_by:  entry.scannedBy   || null,
          mgr_review:  entry.mgrReview   || false,
          return_date: entry.date        || new Date().toISOString().slice(0,10),
          return_time: entry.time        || '00:00:00'
        });
        if (r) saved++;
      }
      log('  ✓ Saved ' + saved + ' / ' + list.length + ' returns', saved === list.length ? 'green' : 'yellow');
      if (saved === list.length) ok++; else fail++;
    }
  } catch(e) {
    log('  ✗ Returns parse error: ' + e.message, 'red');
    fail++;
  }

  // ── 3. VEHICLE TRIPS ───────────────────────────────────────────────
  log('\n[3/6] Vehicle Trips', 'yellow');
  try {
    const trips = JSON.parse(localStorage.getItem('warehub_vehicle') || '[]');
    if (!trips.length) {
      log('  · No vehicle trips in localStorage — skipping', 'white');
    } else {
      let saved = 0;
      for (const trip of trips) {
        const r = await call('POST', '/api/vehicle/trips', {
          driver:      trip.driver      || '',
          destination: trip.dest        || trip.destination || '',
          depart_time: trip.depart      || trip.depart_time || null,
          return_time: trip.ret         || trip.return_time || null,
          odo_start:   trip.odoStart    ? parseFloat(trip.odoStart) : null,
          odo_end:     trip.odoEnd      ? parseFloat(trip.odoEnd)   : null,
          miles:       trip.miles       ? parseFloat(trip.miles)    : null,
          notes:       trip.notes       || null,
          trip_date:   trip.date        || new Date().toISOString().slice(0,10)
        });
        if (r) saved++;
      }
      log('  ✓ Saved ' + saved + ' / ' + trips.length + ' trips', saved === trips.length ? 'green' : 'yellow');
      if (saved === trips.length) ok++; else fail++;
    }
  } catch(e) {
    log('  ✗ Vehicle parse error: ' + e.message, 'red');
    fail++;
  }

  // ── 4. FBA SHIPMENTS ───────────────────────────────────────────────
  log('\n[4/6] FBA Shipments', 'yellow');
  try {
    const recs = JSON.parse(localStorage.getItem('warehub_fba') || '[]');
    if (!recs.length) {
      log('  · No FBA records in localStorage — skipping', 'white');
    } else {
      let saved = 0;
      for (const rec of recs) {
        const r = await call('POST', '/api/fba', {
          shipment_id:        rec.shipId   || '',
          fulfillment_center: rec.fc       || null,
          units:              rec.units    ? parseInt(rec.units)    : null,
          boxes:              rec.boxes    ? parseInt(rec.boxes)    : null,
          dims:               rec.dims     || null,
          weight:             rec.weight   ? parseFloat(rec.weight) : null,
          carrier:            rec.carrier  || null,
          tracking:           rec.tracking || null,
          submitted_by:       rec.by       || null,
          notes:              rec.notes    || null,
          ship_date:          rec.date     || new Date().toISOString().slice(0,10),
          skus:               rec.skus     || []
        });
        if (r) saved++;
      }
      log('  ✓ Saved ' + saved + ' / ' + recs.length + ' FBA records', saved === recs.length ? 'green' : 'yellow');
      if (saved === recs.length) ok++; else fail++;
    }
  } catch(e) {
    log('  ✗ FBA parse error: ' + e.message, 'red');
    fail++;
  }

  // ── 5. SETTINGS (vehicle config + FedEx config) ────────────────────
  log('\n[5/6] Settings', 'yellow');
  try {
    const vc = JSON.parse(localStorage.getItem('warehub_vehicle_config') || '{}');
    const fc = JSON.parse(localStorage.getItem('warehub_fedex')          || '{}');
    const payload = {};
    if (vc.model || vc.plate) payload.vehicle_config = vc;
    if (fc.clientId)          payload.fedex_config   = fc;

    if (!Object.keys(payload).length) {
      log('  · No settings in localStorage — skipping', 'white');
    } else {
      const r = await call('POST', '/api/settings', payload);
      if (r) {
        log('  ✓ Settings saved (vehicle + FedEx config)', 'green');
        ok++;
      } else {
        fail++;
      }
    }
  } catch(e) {
    log('  ✗ Settings parse error: ' + e.message, 'red');
    fail++;
  }

  // ── 6. ORDERS (session-based — show count only, no migration needed) ──
  log('\n[6/6] Orders', 'yellow');
  log('  · Orders are session-based (rebuilt from PDF each shift).', 'white');
  log('  · Current session orders auto-sync when imported — no migration needed.', 'white');

  // ── Summary ────────────────────────────────────────────────────────
  log('\n' + LINE, 'cyan');
  if (fail === 0) {
    log('  ✓ Migration complete! ' + ok + ' sections synced with no errors.', 'green');
    log('  Your warehouse data is now live in Cloudflare D1.', 'green');
  } else {
    log('  ⚠ Migration finished with ' + fail + ' error(s). Check output above.', 'yellow');
    log('  Successful: ' + ok + ' section(s). Failed: ' + fail + ' section(s).', 'yellow');
  }
  log(LINE, 'cyan');

})();
