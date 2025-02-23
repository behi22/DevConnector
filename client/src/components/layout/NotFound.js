import React from 'react';
import { Link } from 'react-router-dom';

const NotFound = () => {
  return (
    <div className="notfound-container">
      <div className="notfound-content">
        <h1 className="notfound-title">
          <i className="fas fa-exclamation-triangle" /> 404
        </h1>
        <h2 className="notfound-subtitle">Page Not Found</h2>
        <p className="notfound-text">
          Oops! The page you're looking for can't be found.
        </p>
        <Link to="/" className="notfound-btn">
          Go Home
        </Link>
      </div>
    </div>
  );
};

export default NotFound;
