// Vulnerable code examples for testing XSS detection

import React from 'react';

// VULNERABLE: Unsanitized dangerouslySetInnerHTML
export function VulnerableComponent1({ userContent }: { userContent: string }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: userContent }} />
  );
}

// VULNERABLE: User input in dangerouslySetInnerHTML
export function VulnerableComponent2({ comment }: { comment: any }) {
  return (
    <div 
      className="comment"
      dangerouslySetInnerHTML={{ __html: comment.content }}
    />
  );
}

// VULNERABLE: Template with user input
export function VulnerableComponent3({ title, description }: any) {
  const htmlContent = `
    <h1>${title}</h1>
    <p>${description}</p>
  `;
  
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}

// VULNERABLE: Dynamic script injection
export function VulnerableComponent4({ userScript }: { userScript: string }) {
  return (
    <div>
      <script dangerouslySetInnerHTML={{ __html: userScript }} />
    </div>
  );
}

// VULNERABLE: innerHTML assignment (simulated)
export function VulnerableComponent5({ content }: { content: string }) {
  React.useEffect(() => {
    const element = document.getElementById('content');
    if (element) {
      element.innerHTML = content; // VULNERABLE: Direct innerHTML
    }
  }, [content]);
  
  return <div id="content" />;
}

// VULNERABLE: URL-based XSS
export function VulnerableComponent6() {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message') || '';
  
  return (
    <div dangerouslySetInnerHTML={{ __html: `<p>Message: ${message}</p>` }} />
  );
}

// SECURE: Properly sanitized content
export function SecureComponent1({ userContent }: { userContent: string }) {
  const DOMPurify = require('dompurify');
  const sanitizedContent = DOMPurify.sanitize(userContent);
  
  return (
    <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
  );
}

// SECURE: Using text content instead of HTML
export function SecureComponent2({ userContent }: { userContent: string }) {
  return <div>{userContent}</div>; // React automatically escapes
}

// SECURE: Sanitization with allowlist
export function SecureComponent3({ content }: { content: string }) {
  const DOMPurify = require('dompurify');
  const config = { ALLOWED_TAGS: ['b', 'i', 'p'], ALLOWED_ATTR: [] };
  const clean = DOMPurify.sanitize(content, config);
  
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}