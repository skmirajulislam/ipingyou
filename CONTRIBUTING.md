
# Contributing to iPingYou

Thank you for your interest in contributing to iPingYou 🚀

We welcome contributions from developers, security researchers, students, and open-source enthusiasts.  
To maintain project quality and workflow consistency, please follow the contribution guidelines carefully.

---

# 📌 Before You Start

## 🚨 Important Rule

**DO NOT directly create a Pull Request without discussing the change first.**

All contributors must:

1. Create or find an existing issue
2. Discuss the proposed change
3. Wait for approval or assignment
4. Then submit a Pull Request

Pull Requests without a linked issue may be closed.

---

# 🛠 Development Setup

## 1. Fork the Repository

Fork the repository to your GitHub account.

---

## 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/ipingyou.git
cd ipingyou
````

---

## 3. Install Dependencies

```bash
npm install
```

---

## 4. Configure Environment Variables

Create a `.env` file in the project root.

Example:

```env
PORT=3000
```

---

## 5. Run the Project

```bash
npm start
```

For development:

```bash
npm run dev
```

---

# 📋 Contribution Workflow

## Step 1 — Create an Issue

Before writing code:

* Check existing issues first
* Avoid duplicate issues
* Clearly explain:

  * Problem
  * Proposed solution
  * Expected behavior

Issue types:

* Bug report
* Feature request
* Documentation improvement
* Security issue
* Performance optimization

---

## Step 2 — Wait for Discussion / Approval

Maintainers may:

* Approve the issue
* Request modifications
* Reject the proposal
* Assign the issue

Please do not start large changes before approval.

---

## Step 3 — Create a Branch

Never work directly on `master`.

Branch naming examples:

```bash
feature/add-relay-auth
fix/socket-reconnect
docs/update-api-guide
refactor/improve-session-handler
```

---

## Step 4 — Make Changes

Please ensure:

* Clean and readable code
* Proper formatting
* No unnecessary dependencies
* No unrelated file modifications
* No secrets/API keys committed

---

# ✅ Open Source Standards

All contributions must follow standard open-source practices.

## Required

* Follow existing project structure
* Keep PRs focused and minimal
* Write meaningful commit messages
* Maintain backward compatibility when possible
* Respect code review feedback

---

## Prohibited

Do NOT:

* Submit AI-generated spam PRs
* Open duplicate PRs
* Force push unrelated changes
* Reformat the entire codebase unnecessarily
* Add unnecessary packages
* Commit `node_modules`
* Commit `.env` files or secrets
* Submit plagiarized code

Violation of these standards may result in PR rejection.

---

# 🧪 Testing

Before submitting a PR:

```bash
npm test
```

Also verify:

* Application runs correctly
* No console errors
* No linting issues
* Existing functionality remains stable

---

# 📝 Commit Message Convention

Use professional commit messages.

Examples:

```bash
feat: add encrypted relay validation
fix: resolve socket timeout issue
docs: improve setup instructions
refactor: optimize broker routing
```

---

# 🔀 Pull Request Guidelines

## Before Opening a PR

Ensure:

* The issue exists
* The issue is referenced in the PR
* Your branch is updated
* Tests pass successfully

---

## PR Title Format

Examples:

```bash
fix: reconnect issue in relay server
feat: add secure session validation
docs: improve contributing guide
```

---

## PR Description Must Include

* Related issue number
* Summary of changes
* Screenshots (if applicable)
* Testing details

Example:

```md
Closes #12

## Changes
- Fixed relay reconnect issue
- Improved timeout handling

## Tested
- Local testing completed successfully
```

---

# 🔒 Security Contributions

If you discover a security vulnerability:

❌ Do NOT create a public issue.

Instead, contact the maintainer privately and provide detailed reproduction steps.

---

# 🤝 Code of Conduct

Please maintain a respectful and collaborative environment.

Be professional.
Be constructive.
Respect all contributors.

---

# ⭐ Support the Project

If you find this project useful:

* Star the repository
* Share the project
* Report issues responsibly
* Contribute improvements

---

# 👨‍💻 Maintainer

SK Mirajul Islam

GitHub: [https://github.com/skmirajulislam](https://github.com/skmirajulislam)
Email: skmirajulislam181@gmail.com

---

Happy Contributing 🚀

```
```
