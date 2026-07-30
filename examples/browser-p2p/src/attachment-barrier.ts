export class AttachmentBarrier {
  #localReady = false;
  #remoteReady = false;
  #started = false;

  markLocalReady(): boolean {
    if (this.#localReady) {
      return false;
    }
    this.#localReady = true;
    return this.#takeReady();
  }

  markRemoteReady(): boolean {
    if (this.#remoteReady) {
      return false;
    }
    this.#remoteReady = true;
    return this.#takeReady();
  }

  #takeReady(): boolean {
    if (this.#started || !this.#localReady || !this.#remoteReady) {
      return false;
    }
    this.#started = true;
    return true;
  }
}
