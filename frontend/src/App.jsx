import {BrowserRouter, Link} from 'react-router-dom'
import Navbar from './Components/Navbar/Navbar';
import Card from './Components/Card/Card';

import Home from "./Pages/Home/Home";

const App = ()=> {
  return (
    <>
      <BrowserRouter>
        <Home />
      </BrowserRouter>
    </>
  );
}

export default App;