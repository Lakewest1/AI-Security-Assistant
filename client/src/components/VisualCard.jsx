import React, { useState } from "react";

const VisualCard = ({ visualData }) => {
  const [imageError, setImageError] = useState(false);
  const [loaded, setLoaded] = useState(false);

  if (!visualData || !visualData.needed) {
    return null;
  }

  // Placeholder for future implementation
  // Will be connected to media providers later
  return (
    <div className="visual-card">
      <div className="visual-card-header">
        <span className="visual-icon">📊</span>
        <span>Visual Learning</span>
      </div>
      <div className="visual-card-body">
        {imageError ? (
          <div className="visual-error">
            Visual unavailable
            <span>Continue reading the explanation.</span>
          </div>
        ) : (
          <div className="visual-placeholder">
            <div className="placeholder-icon">🔍</div>
            <p>Visual content coming soon</p>
            <span>We're preparing diagram support</span>
          </div>
        )}
      </div>
      {visualData.query && (
        <div className="visual-card-footer">
          <span>Topic: {visualData.query}</span>
        </div>
      )}
    </div>
  );
};

export default VisualCard;