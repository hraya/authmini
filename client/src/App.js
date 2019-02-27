import React, { Component } from "react";
import { Route, NavLink } from "react-router-dom";

import Users from "./users/Users.js";
import Signin from "./auth/Signin.js"

import "./App.css";

const Home = props => {
  return <div>Home Components</div>;
};

class App extends Component {

  signout = () =>{
    localStorage.removeItem('jwt');
  }

  render() {
    return (
      <div className="App">
        <header className="App-header">
          <nav>
            <NavLink exact to="/">
              Home
            </NavLink>
            &nbsp; | &nbsp;
            <NavLink to="/users">Users</NavLink>
            &nbsp; | &nbsp;
            <NavLink to="/signin">Signin</NavLink>
            &nbsp; | &nbsp;
            <button onClick={this.signout}>Sign Out</button>
          </nav>
          <main>
            <Route exact path="/" component={Home} />
            <Route path="/users" component={Users} />
            <Route path="/signin" component={Signin} />
          </main>
        </header>
      </div>
    );
  }
}

export default App;
