import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth';

const firebaseConfig = {
  apiKey: 'AIzaSyDm5L1u6WdPNK1blSRf3QojYfJNCOpw4kU',
  authDomain: 'leverpapers-blog.firebaseapp.com',
  projectId: 'leverpapers-blog',
  storageBucket: 'leverpapers-blog.appspot.com',
  messagingSenderId: '626672863169',
  appId: '1:626672863169:web:67587b51b4c04a3a1e1140',
};

const app = initializeApp(firebaseConfig);

//Google auth
const provider = new GoogleAuthProvider();
const auth = getAuth();
export const authWithGoogle = async () => {
  let user = null;
  await signInWithPopup(auth, provider)
    .then((result) => {
      user = result.user;
    })
    .catch((err) => {
      console.log(err);
    });

  return user;
};
