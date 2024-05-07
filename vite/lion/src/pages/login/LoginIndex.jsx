import axios from "axios";
import sha256 from "crypto-js/sha256";
import { Fragment, useState } from "react";
import { Button, Col, Container, Form, Row } from "react-bootstrap";
import VerifiedUser from "./components/VerifiedUser";
import { useAuth } from "../../context/AuthProvider";

export default function LoginIndex() {
  const { login } = useAuth();

  const [users_email, setUsers_email] = useState("root@dev.com");
  const [users_password, setUsers_password] = useState("lion");
  const [verified, setVerified] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();

    const form = {
      users_email: users_email,
      users_password: sha256(users_password).toString(),
    };

    axios
      .post(`${import.meta.env.VITE_SERVER_URL_AUD}/api/auth/login`, form)
      .then(({ data }) => {
        console.log(data);

        if ("success" === data.status) {
          login(data.data.jwt);
        }
      })
      .catch(({ response }) => {
        console.log(response.data);

        if (403 === response.data.code) {
          setVerified(true);
        }
      });
  };

  return (
    <Fragment>
      <Container>
        <Row>
          <Col
            xs={12}
            sm={12}
            md={8}
            lg={7}
            xl={5}
            xxl={5}
            className="mx-auto my-5 bg-light border rounded p-3"
          >
            {verified ? (
              <VerifiedUser
                users_email={users_email}
                setVerified={setVerified}
              />
            ) : (
              <Fragment>
                <h4>Login</h4>

                <hr />

                <Form onSubmit={handleSubmit}>
                  <Form.Group as={Row} className="mb-3" controlId="users_email">
                    <Form.Label column sm="2">
                      Email
                    </Form.Label>

                    <Col sm="10">
                      <Form.Control
                        value={users_email}
                        onChange={(e) => setUsers_email(e.target.value)}
                        type="email"
                        placeholder="Email..."
                        required
                      />
                    </Col>
                  </Form.Group>

                  <Form.Group
                    as={Row}
                    className="mb-3"
                    controlId="users_password"
                  >
                    <Form.Label column sm="2">
                      Password
                    </Form.Label>

                    <Col sm="10">
                      <Form.Control
                        value={users_password}
                        onChange={(e) => setUsers_password(e.target.value)}
                        type="password"
                        placeholder="Password..."
                        autoComplete="off"
                      />
                    </Col>
                  </Form.Group>

                  <Button type="submit" variant="success" className="float-end">
                    Login
                  </Button>
                </Form>
              </Fragment>
            )}
          </Col>
        </Row>
      </Container>
    </Fragment>
  );
}
