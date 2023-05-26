import React from "react";
import { Route, Navigate } from "react-router-dom";

export const ProtectedRoute = ({ component: Component, ...rest }) => {
  const isAuthenticated = localStorage.getItem("token");

  return (
    <Route
      {...rest}
      render={(props) =>
        isAuthenticated ? (
          <Component {...props} />
        ) : (
          <Navigate to="/Login" replace />

        )
      }
    />
  );
};
