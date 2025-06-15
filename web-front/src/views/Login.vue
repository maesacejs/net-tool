<template>
  <div class="container">
    <div class="container is-max-tablet">
      <div class="card-image has-text-centered">
      <figure class="image is-128x128 is-inline-block">
        <img src="../assets/web-logo.jpg"/>
      </figure>
      <h1 class="box bit-smaler">Informational tool for local networks</h1>
    </div>
    
    <form class="box bit-smaler" @submit.prevent="submitLogin()">
      <div>
        <label for="username">Username:</label>
        <input type="text" v-model="username" id="username" required />
      </div>
      <div>
        <label for="password">Password:</label>
        <input type="password" v-model="password" id="password" required />
      </div>
      <button class="button is-small is-dark">Login</button>
      <p v-if="error" class="error top-buffer">{{ error }}</p>
    </form>
  </div>
  </div>
</template>

<script>
import { mapState, mapActions } from 'vuex';

export default {
  data() {
    return {
      username: '',
      password: '',
    };
  },
  computed: {
    ...mapState(['error']),
  },
  methods: {
    ...mapActions(['login']),

    async submitLogin() {
      const credentials = {
        "username": this.username,
        "password": this.password
      }
      try {
        const req = await this.login(credentials)
        if (req === true) {
          this.$router.push('/devices');
        }
      } catch (err) {
        console.log(err)
        console.log("Error but not from API")
      }
    }

  },
};
</script>

<style scoped>
.container {
  margin-top: 2em;
}

.top-buffer {
    margin-top: 25px;
  }

.bit-smaler{
  margin-left: 15%;
  max-width: 70%;
}

input {
  margin: 10px 0;
  padding: 8px;
  width: 100%;
}

button {
  background-color: #1200b7;
  color: white;
  padding: 10px;
  margin-left: 25%;
  width: 50%;
}

.error {
  color: red;
}
</style>