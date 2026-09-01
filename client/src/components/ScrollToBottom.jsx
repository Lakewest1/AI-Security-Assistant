import React from "react";

const ScrollToBottom = ({ onClick }) => {
  return (
    <button className="scroll-button" onClick={onClick} aria-label="Scroll to bottom">
      ↓ Scroll to bottom
    </button>
  );
};

export default ScrollToBottom;