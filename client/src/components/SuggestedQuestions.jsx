import React from "react";

const SuggestedQuestions = ({ onQuestionClick }) => {
  const questions = [
    "How do I secure my AWS S3 buckets?",
    "Explain Kubernetes security best practices",
    "What is the AWS shared responsibility model?",
    "How does a WAF protect applications?",
    "What are IAM roles vs policies?",
    "How to detect and respond to security incidents?",
  ];

  return (
    <div className="suggestions-container">
      <p className="suggestions-title">Try asking about:</p>
      <div className="suggestions-list">
        {questions.map((question, index) => (
          <button
            key={index}
            className="suggestion-chip"
            onClick={() => onQuestionClick(question)}
          >
            {question}
          </button>
        ))}
      </div>
    </div>
  );
};

export default SuggestedQuestions;