import React, { useEffect } from "react";

import { Row, Col } from "reactstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import contentData from "../utils/contentData";

import { useAuth0 } from "@auth0/auth0-react";
import { getConfig } from "../config";

const Content = () => {
  const { isAuthenticated, getIdTokenClaims } = useAuth0();

  useEffect(() => {
    const fetchIdToken = async () => {
      if (!isAuthenticated) {
        console.error("User is not authenticated");
        return;
      }

      const IdToken = await getIdTokenClaims();
      const { __raw, sub } = IdToken;

      const currentSub = localStorage.getItem("sub");
      if (currentSub && currentSub == sub) {
        const res = await fetch(`${apiOrigin}/api/v1/user?sub=${sub}`, {
          method: "GET",
        });

        if (res.status === 200) {
          console.log("Successfully authenticated with the API");
        }

        return;
      }

      if (!__raw) {
        return;
      }

      localStorage.setItem("sub", sub);

      const { apiOrigin = "http://localhost:3001" } = getConfig;
      const res = await fetch(`${apiOrigin}/api/v1/auth0?token=${__raw}`, {
        method: "GET",
      });

      if (res.status === 200) {
        console.log("Successfully authenticated with the API");
      }
    };

    fetchIdToken();
  }, [isAuthenticated, getIdTokenClaims]);

  return (
    <div className="next-steps my-5">
      <h2 className="my-5 text-center">What can I do next?</h2>
      <Row className="d-flex justify-content-between">
        {contentData.map((col, i) => (
          <Col key={i} md={5} className="mb-4">
            <h6 className="mb-3">
              <a href={col.link}>
                <FontAwesomeIcon icon="link" className="mr-2" />
                {col.title}
              </a>
            </h6>
            <p>{col.description}</p>
          </Col>
        ))}
      </Row>
    </div>
  );
};

export default Content;
