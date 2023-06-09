export const nameInput = document.querySelector('.pop-up__input_type_name');
export const descriptionInput = document.querySelector('.pop-up__input_type_description');

export const formAvatar = document.querySelector('.pop-up__form_type_avatar');
export const formAdd = document.querySelector('.pop-up__form_type_add');
export const formEdit = document.querySelector('.pop-up__form_type_edit');

export const buttonAvatar = document.querySelector('.profile__change-avatar-btn');
export const buttonEdit = document.querySelector('.profile__edit-button');
export const buttonAdd = document.querySelector('.profile__add-button');

export const apiOption = {
  token: localStorage.getItem('token'),
  serverLink: 'https://api.dewhiteproject.nomoredomains.monster'
}