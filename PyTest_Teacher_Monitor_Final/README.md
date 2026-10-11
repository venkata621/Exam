# PyTest Arena — Final Teacher Monitoring Project

This ZIP contains the existing 100-question bank (50 Easy, 25 Medium, 25 Hard) and a starter Node.js backend for:
- Student exam via a unique, one-use code.
- Teacher login/dashboard with attempt list, detailed answers, topic performance, and activity logs.
- Consent-based live camera stream to the teacher dashboard. The student page does not show a camera preview.
- SQLite persistence (requires a persistent disk on the host).

## The two links after deployment
If your hosting service gives you `https://YOUR-SERVICE.onrender.com`, then:
- Teacher: `https://YOUR-SERVICE.onrender.com/teacher.html`
- Student: `https://YOUR-SERVICE.onrender.com/`

These are URL patterns, not live links yet. Replace `YOUR-SERVICE` with the actual service name generated after deployment.

## Deploy step-by-step
1. Download and extract this ZIP.
2. Create a GitHub repository at https://github.com/new and upload the extracted project files. Do not upload `.env`, passwords, or database files.
3. Create a Node web service at https://render.com/ and connect the GitHub repository.
4. Set build command `npm install` and start command `npm start`.
5. Set environment variables in the host dashboard:
   - `NODE_ENV=production`
   - `TEACHER_USERNAME` (your chosen username)
   - `TEACHER_PASSWORD_HASH` (bcrypt hash; generate using `node -e "console.log(require('bcryptjs').hashSync('Choose-A-Strong-Password', 12))"` after installing dependencies)
   - `SESSION_SECRET` (a long random secret)
   - `DB_PATH` (path on a persistent disk, e.g. `/var/data/pytest.sqlite`)
6. Attach a persistent disk and set `DB_PATH` to a path on that disk. If SQLite is on ephemeral storage, data may disappear during redeploys.
7. Deploy and wait for a successful build. Copy the public service URL shown by the host.
8. Open the teacher link (`/teacher.html`), log in, and generate an exam code.
9. Send the student link (`/`) and the unique code to your student.
10. Student enters code, reads the camera-monitoring notice, consents, and grants browser camera permission. Teacher opens that attempt's Details / Monitor page to view the live stream and report.

## Privacy and limitations
- Camera preview is not displayed on the student's exam page, but the student is clearly notified that camera monitoring is active and the browser's normal camera indicator remains visible.
- This starter streams video live; it does not record/store camera video.
- Activity logs include exam start/submission, consent, camera start, tab visibility, fullscreen changes, and connectivity events. These are signals, not proof of cheating.
- HTTPS is required for camera access on devices other than localhost.
- This is a starter project, not production-audited. Before a real exam, add rate limiting, CSRF protection, server-side timing, robust resume support, stronger authorization for WebRTC signaling, and test data persistence. Do not use for high-stakes exams until security-reviewed.
