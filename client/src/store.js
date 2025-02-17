import { configureStore } from '@reduxjs/toolkit';
import thunk from 'redux-thunk';
import rootReducer from './reducers';

const initialState = {};

const middleware = [thunk];

const store = configureStore({
  reducer: rootReducer,
  preloadedState: initialState,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(middleware),
});

export default store;
