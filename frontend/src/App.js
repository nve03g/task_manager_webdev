// to run this file: npm start

import React, {useState, useEffect} from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom'; // to define routes and render specific components based on the current URL
import './App.css';
//import { response } from 'express'; // don't use this! the 'express' package is a server-side package, and shouldn't be included on the client-side

function UserTable(){
  const [users, setUsers] = useState([]);

  // fetch data from the backend
  useEffect(() => {
    fetch('https://localhost:443/users')
      .then((response) => response.json())
      .then((data) => setUsers(data))
      .catch((error) => console.error('Error fetching users:', error));
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>User data</h1>
        <table>
          <thead>
            <tr>
              <th>User ID</th>
              <th>Username</th>
              <th>Password</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.userID}>
                <td>{user.userID}</td>
                <td>{user.username}</td>
                <td>{user.password}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p>Go back to <Link to="/home">Home</Link>.</p>
      </header>
    </div>
  );
}

function Home(){
  return (
    <div>
      <h1>Welcome to the App</h1>
      <p>Navigate to <Link to="/users">Users</Link> to view the user table.</p>
    </div>
  );
}

function NotFound() {
  return (
    <div>
      <h1>404 - Page Not Found</h1>
      <p>Sorry, the page you are looking for does not exist.</p>
      <p>
        Go back to <Link to="/home">Home</Link>.
      </p>
    </div>
  );
}

function App() {
  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <Routes>
            <Route path="/home" element={<Home />} />
            <Route path="/users" element={<UserTable />} />
            <Route path="*" element={<NotFound />} /> {/* any unknown route results in an error message */}
          </Routes>
        </header>
      </div>
    </Router>
  );
}

export default App;
